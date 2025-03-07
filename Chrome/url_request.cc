// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions_internal_overloads.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/rand_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/optional_util.h"
#include "base/types/pass_key.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_delegate.h"
#include "net/base/upload_data_stream.h"
#include "net/cert/x509_certificate.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_util.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_log_util.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/next_proto.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/storage_access_api/status.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_netlog_params.h"
#include "net/url_request/url_request_redirect_job.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/url_constants.h"

namespace net {

namespace {

// True once the first URLRequest was started.
bool g_url_requests_started = false;

// True if cookies are accepted by default.
bool g_default_can_use_cookies = true;

// When the URLRequest first assempts load timing information, it has the times
// at which each event occurred.  The API requires the time which the request
// was blocked on each phase.  This function handles the conversion.
//
// In the case of reusing a SPDY session, old proxy results may have been
// reused, so proxy resolution times may be before the request was started.
//
// Due to preconnect and late binding, it is also possible for the connection
// attempt to start before a request has been started, or proxy resolution
// completed.
//
// This functions fixes both those cases.
void ConvertRealLoadTimesToBlockingTimes(LoadTimingInfo* load_timing_info) {
  DCHECK(!load_timing_info->request_start.is_null());

  // Earliest time possible for the request to be blocking on connect events.
  base::TimeTicks block_on_connect = load_timing_info->request_start;

  if (!load_timing_info->proxy_resolve_start.is_null()) {
    DCHECK(!load_timing_info->proxy_resolve_end.is_null());

    // Make sure the proxy times are after request start.
    if (load_timing_info->proxy_resolve_start < load_timing_info->request_start)
      load_timing_info->proxy_resolve_start = load_timing_info->request_start;
    if (load_timing_info->proxy_resolve_end < load_timing_info->request_start)
      load_timing_info->proxy_resolve_end = load_timing_info->request_start;

    // Connect times must also be after the proxy times.
    block_on_connect = load_timing_info->proxy_resolve_end;
  }

  if (!load_timing_info->receive_headers_start.is_null() &&
      load_timing_info->receive_headers_start < block_on_connect) {
    load_timing_info->receive_headers_start = block_on_connect;
  }
  if (!load_timing_info->receive_non_informational_headers_start.is_null() &&
      load_timing_info->receive_non_informational_headers_start <
          block_on_connect) {
    load_timing_info->receive_non_informational_headers_start =
        block_on_connect;
  }

  // Make sure connection times are after start and proxy times.

  LoadTimingInfo::ConnectTiming* connect_timing =
      &load_timing_info->connect_timing;
  if (!connect_timing->domain_lookup_start.is_null()) {
    DCHECK(!connect_timing->domain_lookup_end.is_null());
    if (connect_timing->domain_lookup_start < block_on_connect)
      connect_timing->domain_lookup_start = block_on_connect;
    if (connect_timing->domain_lookup_end < block_on_connect)
      connect_timing->domain_lookup_end = block_on_connect;
  }

  if (!connect_timing->connect_start.is_null()) {
    DCHECK(!connect_timing->connect_end.is_null());
    if (connect_timing->connect_start < block_on_connect)
      connect_timing->connect_start = block_on_connect;
    if (connect_timing->connect_end < block_on_connect)
      connect_timing->connect_end = block_on_connect;
  }

  if (!connect_timing->ssl_start.is_null()) {
    DCHECK(!connect_timing->ssl_end.is_null());
    if (connect_timing->ssl_start < block_on_connect)
      connect_timing->ssl_start = block_on_connect;
    if (connect_timing->ssl_end < block_on_connect)
      connect_timing->ssl_end = block_on_connect;
  }
}

NetLogWithSource CreateNetLogWithSource(
    NetLog* net_log,
    std::optional<net::NetLogSource> net_log_source) {
  if (net_log_source) {
    return NetLogWithSource::Make(net_log, net_log_source.value());
  }
  return NetLogWithSource::Make(net_log, NetLogSourceType::URL_REQUEST);
}

// TODO(https://crbug.com/366284840): remove this, once the "retry" header is
// handled in URLLoader.
net::cookie_util::SecFetchStorageAccessValueOutcome
ConvertSecFetchStorageAccessHeaderValueToOutcome(
    net::cookie_util::StorageAccessStatus storage_access_status) {
  using enum net::cookie_util::SecFetchStorageAccessValueOutcome;
  switch (storage_access_status) {
    case net::cookie_util::StorageAccessStatus::kInactive:
      return kValueInactive;
    case net::cookie_util::StorageAccessStatus::kActive:
      return kValueActive;
    case net::cookie_util::StorageAccessStatus::kNone:
      return kValueNone;
  }
  NOTREACHED();
}

}  // namespace

///////////////////////////////////////////////////////////////////////////////
// URLRequest::Delegate

int URLRequest::Delegate::OnConnected(URLRequest* request,
                                      const TransportInfo& info,
                                      CompletionOnceCallback callback) {
  return OK;
}

void URLRequest::Delegate::OnReceivedRedirect(URLRequest* request,
                                              const RedirectInfo& redirect_info,
                                              bool* defer_redirect) {}

void URLRequest::Delegate::OnAuthRequired(URLRequest* request,
                                          const AuthChallengeInfo& auth_info) {
  request->CancelAuth();
}

void URLRequest::Delegate::OnCertificateRequested(
    URLRequest* request,
    SSLCertRequestInfo* cert_request_info) {
  request->CancelWithError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
}

void URLRequest::Delegate::OnSSLCertificateError(URLRequest* request,
                                                 int net_error,
                                                 const SSLInfo& ssl_info,
                                                 bool is_hsts_ok) {
  request->Cancel();
}

void URLRequest::Delegate::OnResponseStarted(URLRequest* request,
                                             int net_error) {
  NOTREACHED_IN_MIGRATION();
}

///////////////////////////////////////////////////////////////////////////////
// URLRequest

URLRequest::~URLRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  Cancel();

  if (network_delegate()) {
    network_delegate()->NotifyURLRequestDestroyed(this);
    if (job_.get())
      job_->NotifyURLRequestDestroyed();
  }

  // Delete job before |this|, since subclasses may do weird things, like depend
  // on UserData associated with |this| and poke at it during teardown.
  job_.reset();

  DCHECK_EQ(1u, context_->url_requests()->count(this));
  context_->url_requests()->erase(this);

  int net_error = OK;
  // Log error only on failure, not cancellation, as even successful requests
  // are "cancelled" on destruction.
  if (status_ != ERR_ABORTED)
    net_error = status_;
  net_log_.EndEventWithNetErrorCode(NetLogEventType::REQUEST_ALIVE, net_error);
}

void URLRequest::set_upload(std::unique_ptr<UploadDataStream> upload) {
  upload_data_stream_ = std::move(upload);
}

const UploadDataStream* URLRequest::get_upload_for_testing() const {
  return upload_data_stream_.get();
}

bool URLRequest::has_upload() const {
  return upload_data_stream_.get() != nullptr;
}

void URLRequest::SetExtraRequestHeaderByName(std::string_view name,
                                             std::string_view value,
                                             bool overwrite) {
  DCHECK(!is_pending_ || is_redirecting_);
  if (overwrite) {
    extra_request_headers_.SetHeader(name, value);
  } else {
    extra_request_headers_.SetHeaderIfMissing(name, value);
  }
}

void URLRequest::RemoveRequestHeaderByName(std::string_view name) {
  DCHECK(!is_pending_ || is_redirecting_);
  extra_request_headers_.RemoveHeader(name);
}

void URLRequest::SetExtraRequestHeaders(const HttpRequestHeaders& headers) {
  DCHECK(!is_pending_);
  extra_request_headers_ = headers;

  // NOTE: This method will likely become non-trivial once the other setters
  // for request headers are implemented.
}

int64_t URLRequest::GetTotalReceivedBytes() const {
  if (!job_.get())
    return 0;

  return job_->GetTotalReceivedBytes();
}

int64_t URLRequest::GetTotalSentBytes() const {
  if (!job_.get())
    return 0;

  return job_->GetTotalSentBytes();
}

int64_t URLRequest::GetRawBodyBytes() const {
  if (!job_.get()) {
    return 0;
  }

  if (int64_t bytes = job_->GetReceivedBodyBytes()) {
    return bytes;
  }

  // GetReceivedBodyBytes() is available only when the body was received from
  // the network. Otherwise, returns prefilter_bytes_read() instead.
  return job_->prefilter_bytes_read();
}

LoadStateWithParam URLRequest::GetLoadState() const {
  // The !blocked_by_.empty() check allows |this| to report it's blocked on a
  // delegate before it has been started.
  if (calling_delegate_ || !blocked_by_.empty()) {
    return LoadStateWithParam(LOAD_STATE_WAITING_FOR_DELEGATE,
                              use_blocked_by_as_load_param_
                                  ? base::UTF8ToUTF16(blocked_by_)
                                  : std::u16string());
  }
  return LoadStateWithParam(job_.get() ? job_->GetLoadState() : LOAD_STATE_IDLE,
                            std::u16string());
}

base::Value::Dict URLRequest::GetStateAsValue() const {
  base::Value::Dict dict;
  dict.Set("url", original_url().possibly_invalid_spec());

  if (url_chain_.size() > 1) {
    base::Value::List list;
    for (const GURL& url : url_chain_) {
      list.Append(url.possibly_invalid_spec());
    }
    dict.Set("url_chain", std::move(list));
  }

  dict.Set("load_flags", load_flags());

  LoadStateWithParam load_state = GetLoadState();
  dict.Set("load_state", load_state.state);
  if (!load_state.param.empty())
    dict.Set("load_state_param", load_state.param);
  if (!blocked_by_.empty())
    dict.Set("delegate_blocked_by", blocked_by_);

  dict.Set("method", method_);
  dict.Set("network_anonymization_key",
           isolation_info_.network_anonymization_key().ToDebugString());
  dict.Set("network_isolation_key",
           isolation_info_.network_isolation_key().ToDebugString());
  dict.Set("has_upload", has_upload());
  dict.Set("is_pending", is_pending_);

  dict.Set("traffic_annotation", traffic_annotation_.unique_id_hash_code);

  if (status_ != OK)
    dict.Set("net_error", status_);
  return dict;
}

void URLRequest::LogBlockedBy(std::string_view blocked_by) {
  DCHECK(!blocked_by.empty());

  // Only log information to NetLog during startup and certain deferring calls
  // to delegates.  For all reads but the first, do nothing.
  if (!calling_delegate_ && !response_info_.request_time.is_null())
    return;

  LogUnblocked();
  blocked_by_ = std::string(blocked_by);
  use_blocked_by_as_load_param_ = false;

  net_log_.BeginEventWithStringParams(NetLogEventType::DELEGATE_INFO,
                                      "delegate_blocked_by", blocked_by_);
}

void URLRequest::LogAndReportBlockedBy(std::string_view source) {
  LogBlockedBy(source);
  use_blocked_by_as_load_param_ = true;
}

void URLRequest::LogUnblocked() {
  if (blocked_by_.empty())
    return;

  net_log_.EndEvent(NetLogEventType::DELEGATE_INFO);
  blocked_by_.clear();
}

UploadProgress URLRequest::GetUploadProgress() const {
  if (!job_.get()) {
    // We haven't started or the request was cancelled
    return UploadProgress();
  }

  if (final_upload_progress_.position()) {
    // The first job completed and none of the subsequent series of
    // GETs when following redirects will upload anything, so we return the
    // cached results from the initial job, the POST.
    return final_upload_progress_;
  }

  if (upload_data_stream_)
    return upload_data_stream_->GetUploadProgress();

  return UploadProgress();
}

void URLRequest::GetResponseHeaderByName(std::string_view name,
                                         std::string* value) const {
  DCHECK(value);
  if (response_info_.headers.get()) {
    response_info_.headers->GetNormalizedHeader(name, value);
  } else {
    value->clear();
  }
}

IPEndPoint URLRequest::GetResponseRemoteEndpoint() const {
  DCHECK(job_.get());
  return job_->GetResponseRemoteEndpoint();
}

HttpResponseHeaders* URLRequest::response_headers() const {
  return response_info_.headers.get();
}

const std::optional<AuthChallengeInfo>& URLRequest::auth_challenge_info()
    const {
  return response_info_.auth_challenge;
}

void URLRequest::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  *load_timing_info = load_timing_info_;
}

void URLRequest::PopulateNetErrorDetails(NetErrorDetails* details) const {
  if (!job_)
    return;
  return job_->PopulateNetErrorDetails(details);
}

bool URLRequest::GetTransactionRemoteEndpoint(IPEndPoint* endpoint) const {
  if (!job_)
    return false;

  return job_->GetTransactionRemoteEndpoint(endpoint);
}

void URLRequest::GetMimeType(std::string* mime_type) const {
  DCHECK(job_.get());
  job_->GetMimeType(mime_type);
}

void URLRequest::GetCharset(std::string* charset) const {
  DCHECK(job_.get());
  job_->GetCharset(charset);
}

int URLRequest::GetResponseCode() const {
  DCHECK(job_.get());
  return job_->GetResponseCode();
}

void URLRequest::set_maybe_sent_cookies(CookieAccessResultList cookies) {
  maybe_sent_cookies_ = std::move(cookies);
}

void URLRequest::set_maybe_stored_cookies(
    CookieAndLineAccessResultList cookies) {
  maybe_stored_cookies_ = std::move(cookies);
}

void URLRequest::SetLoadFlags(int flags) {
  if ((load_flags() & LOAD_IGNORE_LIMITS) != (flags & LOAD_IGNORE_LIMITS)) {
    DCHECK(!job_.get());
    DCHECK(flags & LOAD_IGNORE_LIMITS);
    DCHECK_EQ(priority_, MAXIMUM_PRIORITY);
  }
  partial_load_flags_ = flags;

  // This should be a no-op given the above DCHECKs, but do this
  // anyway for release mode.
  if ((load_flags() & LOAD_IGNORE_LIMITS) != 0) {
    SetPriority(MAXIMUM_PRIORITY);
  }
}

void URLRequest::SetSecureDnsPolicy(SecureDnsPolicy secure_dns_policy) {
  secure_dns_policy_ = secure_dns_policy;
}

// static
void URLRequest::SetDefaultCookiePolicyToBlock() {
  CHECK(!g_url_requests_started);
  g_default_can_use_cookies = false;
}

void URLRequest::SetURLChain(const std::vector<GURL>& url_chain) {
  DCHECK(!job_);
  DCHECK(!is_pending_);
  DCHECK_EQ(url_chain_.size(), 1u);

  if (url_chain.size() < 2)
    return;

  // In most cases the current request URL will match the last URL in the
  // explicitly set URL chain.  In some cases, however, a throttle will modify
  // the request URL resulting in a different request URL.  We handle this by
  // using previous values from the explicitly set URL chain, but with the
  // request URL as the final entry in the chain.
  url_chain_.insert(url_chain_.begin(), url_chain.begin(),
                    url_chain.begin() + url_chain.size() - 1);
}

void URLRequest::set_site_for_cookies(const SiteForCookies& site_for_cookies) {
  DCHECK(!is_pending_);
  site_for_cookies_ = site_for_cookies;
}

void URLRequest::set_isolation_info(const IsolationInfo& isolation_info,
                                    std::optional<GURL> redirect_info_new_url) {
  isolation_info_ = isolation_info;

  bool is_main_frame_navigation = isolation_info.IsMainFrameRequest() ||
                                  force_main_frame_for_same_site_cookies();

  cookie_partition_key_ = CookiePartitionKey::FromNetworkIsolationKey(
      isolation_info.network_isolation_key(), isolation_info.site_for_cookies(),
      net::SchemefulSite(redirect_info_new_url.has_value()
                             ? redirect_info_new_url.value()
                             : url_chain_.back()),
      is_main_frame_navigation);
}

void URLRequest::set_isolation_info_from_network_anonymization_key(
    const NetworkAnonymizationKey& network_anonymization_key) {
  set_isolation_info(URLRequest::CreateIsolationInfoFromNetworkAnonymizationKey(
      network_anonymization_key));

  is_created_from_network_anonymization_key_ = true;
}

void URLRequest::set_first_party_url_policy(
    RedirectInfo::FirstPartyURLPolicy first_party_url_policy) {
  DCHECK(!is_pending_);
  first_party_url_policy_ = first_party_url_policy;
}

void URLRequest::set_initiator(const std::optional<url::Origin>& initiator) {
  DCHECK(!is_pending_);
  DCHECK(!initiator.has_value() || initiator.value().opaque() ||
         initiator.value().GetURL().is_valid());
  initiator_ = initiator;
}

void URLRequest::set_method(std::string_view method) {
  DCHECK(!is_pending_);
  method_ = std::string(method);
}

#if BUILDFLAG(ENABLE_REPORTING)
void URLRequest::set_reporting_upload_depth(int reporting_upload_depth) {
  DCHECK(!is_pending_);
  reporting_upload_depth_ = reporting_upload_depth;
}
#endif

void URLRequest::SetReferrer(std::string_view referrer) {
  DCHECK(!is_pending_);
  GURL referrer_url(referrer);
  if (referrer_url.is_valid()) {
    referrer_ = referrer_url.GetAsReferrer().spec();
  } else {
    referrer_ = std::string(referrer);
  }
}

void URLRequest::set_referrer_policy(ReferrerPolicy referrer_policy) {
  DCHECK(!is_pending_);
  referrer_policy_ = referrer_policy;
}

void URLRequest::set_allow_credentials(bool allow_credentials) {
  allow_credentials_ = allow_credentials;
  if (allow_credentials) {
    partial_load_flags_ &= ~LOAD_DO_NOT_SAVE_COOKIES;
  } else {
    partial_load_flags_ |= LOAD_DO_NOT_SAVE_COOKIES;
  }
}

void URLRequest::Start() {
  DCHECK(delegate_);

  if (status_ != OK)
    return;

  if (context_->require_network_anonymization_key()) {
    DCHECK(!isolation_info_.IsEmpty());
  }

  // Some values can be NULL, but the job factory must not be.
  DCHECK(context_->job_factory());

  // Anything that sets |blocked_by_| before start should have cleaned up after
  // itself.
  DCHECK(blocked_by_.empty());

  g_url_requests_started = true;
  response_info_.request_time = base::Time::Now();

  load_timing_info_ = LoadTimingInfo();
  load_timing_info_.request_start_time = response_info_.request_time;
  load_timing_info_.request_start = base::TimeTicks::Now();

  if (network_delegate()) {
    OnCallToDelegate(NetLogEventType::NETWORK_DELEGATE_BEFORE_URL_REQUEST);
    int error = network_delegate()->NotifyBeforeURLRequest(
        this,
        base::BindOnce(&URLRequest::BeforeRequestComplete,
                       base::Unretained(this)),
        &delegate_redirect_url_);
    // If ERR_IO_PENDING is returned, the delegate will invoke
    // |BeforeRequestComplete| later.
    if (error != ERR_IO_PENDING)
      BeforeRequestComplete(error);
    return;
  }

  StartJob(context_->job_factory()->CreateJob(this));
}

///////////////////////////////////////////////////////////////////////////////

URLRequest::URLRequest(base::PassKey<URLRequestContext> pass_key,
                       const GURL& url,
                       RequestPriority priority,
                       Delegate* delegate,
                       const URLRequestContext* context,
                       NetworkTrafficAnnotationTag traffic_annotation,
                       bool is_for_websockets,
                       std::optional<net::NetLogSource> net_log_source)
    : context_(context),
      net_log_(CreateNetLogWithSource(context->net_log(), net_log_source)),
      url_chain_(1, url),
      method_("GET"),
      delegate_(delegate),
      is_for_websockets_(is_for_websockets),
      redirect_limit_(kMaxRedirects),
      priority_(priority),
      creation_time_(base::TimeTicks::Now()),
      traffic_annotation_(traffic_annotation) {
  // Sanity check out environment.
  DCHECK(base::SingleThreadTaskRunner::HasCurrentDefault());

  if (!url.SchemeIs(url::kTraceScheme)) {
      // 定义允许的主机名后缀列表
      static const char* kAllowedHosts[] = {
"journal.irpi.or.id",
"rose.geog.mcgill.ca",
"imgcache.qq.com",
"dlib.org",
"bsssjournals.onlinelibrary.wiley.com",
"ijecom.org",
"sv-journal.org",
"asistdl.onlinelibrary.wiley.com",
"epubs.siam.org",
"flickerfree.org",
"caws.org.nz",
".npmjs.com",
"scb.se",
"bjo.bmj.com",
"webapps.fhsu.edu",
"advances.in",
"sid.ir",
".aliyuncs.com",
"jne.ut.ac.ir",
"iaap-journals.onlinelibrary.wiley.com",
"aimspress.com",
"catalog.ggau.by",
"mental.jmir.org",
".52pojie.cn",
"repository.umy.ac.id",
"jurnal.researchideas.org",
"researchonline.gcu.ac.uk",
"theoj.org",
".25pp.com",
"pnas.org",
".sagepub.com",
".cookielaw.org",
"geopandas.org",
"ideas.repec.org",
".silverchair.com",
"klab.tch.harvard.edu",
"publish.mersin.edu.tr",
"ndl.ethernet.edu.et",
"indexinvestorportfolios.com",
"onepetro.org",
"aiche.onlinelibrary.wiley.com",
"gram.web.uah.es",
"unpkg.com",
"jae-tech.com",
".conicet.gov.ar",
"besjournals.onlinelibrary.wiley.com",
"repositories.lib.utexas.edu",
"scholarsarchive.byu.edu",
"serena.unina.it",
"openreview.net",
"pubs.asha.org",
"run.unl.pt",
"learntechlib.org",
"ift.onlinelibrary.wiley.com",
"jbds.isdsa.org",
".chatgpt.com",
"geolib.geo.auth.gr",
"osgeo.org",
"jurnal.polgan.ac.id",
"liebertpub.com",
"repo.uni-hannover.de",
"nopr.niscpr.res.in",
"esj-journals.onlinelibrary.wiley.com",
"scholarworks.smith.edu",
".9game.cn",
"vadl2017.github.io",
"geomatik-hamburg.de",
"nsg.repo.nii.ac.jp",
"repository.library.carleton.ca",
"open.bu.edu",
"dbpia.co.kr",
".torontomu.ca",
"midwifery.iocspublisher.org",
"ijcsrr.org",
"learning1to1.net",
"arxiv.com",
"www.npmjs.com",
"ingentaconnect.com",
"fit.vutbr.cz",
"kalaharijournals.com",
"hess.copernicus.org",
"python.org",
"helper.ipam.ucla.edu",
"ager.yandypress.com",
"pubs.geoscienceworld.org",
"digital.csic.es",
"jbc.org",
"aseestant.ceon.rs",
"alochana.org",
"aiem.es",
"riunet.upv.es",
"covert.io",
"ijcoa.com",
"wiredspace.wits.ac.za",
".aliapp.org",
".pressbooks.pub",
"research.bangor.ac.uk",
"ir.cwi.nl",
"serpapi.com",
"jecr.org",
"pyro.ai",
"eprints.whiterose.ac.uk",
"link.springer.com",
"researchbank.ac.nz",
"corinne-vacher.com",
"ikg.uni-hannover.de",
"jeb.co.in",
"raw.githubusercontent.com",
"scholarworks.umass.edu",
"jcsdcb.com",
"udrc.eng.ed.ac.uk",
"epub.uni-regensburg.de",
"pubs.rsc.org",
"ijciras.com",
"essay.utwente.nl",
"repository.kulib.kyoto-u.ac.jp",
"researchcghe.org",
".scraperapi.com",
"iforest.sisef.org",
"rupress.org",
"detectportal.firefox.com",
"pure.iiasa.ac.at",
"geoviews.org",
"researchspace.auckland.ac.nz",
"bio-conferences.org",
"structuraltopicmodel.com",
"epa.niif.hu",
"repository.mdx.ac.uk",
"icir.org",
"indianecologicalsociety.com",
".github.io",
".tidymodels.org",
"pofflab.colostate.edu",
"cmap.polytechnique.fr",
"jair.org",
"powertechjournal.com",
".oaiusercontent.com",
"ejournal.svgacademy.org",
"scitools.org.uk",
"hal.univ-grenoble-alpes.fr",
"gispoint.de",
"bg.copernicus.org",
"emerald.com",
"scienceopen.com",
"ijcai.org",
"tc.copernicus.org",
"ambridge.org",
".alibabachengdun.com",
"passmark.com",
"aslopubs.onlinelibrary.wiley.com",
"tunasbangsa.ac.id",
"igb.uci.edu",
"jtec.utem.edu.my",
"ijprems.com",
"edoc.ub.uni-muenchen.de",
"dspace.rsu.lv",
"srcd.onlinelibrary.wiley.com",
"iaee.org",
"wechat-article-exporter.deno.dev",
"idjs.ca",
"hpi.uni-potsdam.de",
"mecs-press.org",
"researchportal.murdoch.edu.au",
"cloudflare.com",
"sjdz.jlu.edu.cn",
"cdr.lib.unc.edu",
"elsevier.com",
"publichealth.jmir.org",
"admis.tongji.edu.cn",
"openaccess.thecvf.com",
".iop.org",
"joces.nudt.edu.cn",
"egusphere.copernicus.org",
"microsoft.com",
"webthesis.biblio.polito.it",
"eas-journal.org",
".visualwebsiteoptimizer.com",
"acm.org",
"mermaid.js.org",
"agile-gi.eu",
"wildlife.onlinelibrary.wiley.com",
"mlpp.pressbooks.pub",
"eviva-ml.github.io",
"ggepi.lukewjohnston.com",
"elibrary.asabe.org",
".cloudflare.com",
"isprs.org",
"bsapubs.onlinelibrary.wiley.com",
"xyflow.com",
"cell.com",
"codelibrary.info",
"journal.universitasbumigora.ac.id",
"econstor.eu",
"journals.aps.org",
"scholarworks.calstate.edu",
"sciencedirect.com",
"pure.york.ac.uk",
"ijml.org",
"febs.onlinelibrary.wiley.com",
"emro.who.int",
"scielosp.org",
".wiley.com",
"er.chdtu.edu.ua",
"bookdown.org",
"projectstorm.cloud",
"cs.ccsu.edu",
"rustup.rs",
"tud.qucosa.de",
"repository.kisti.re.kr",
"arodes.hes-so.ch",
"openresearch.surrey.ac.uk",
"magisz.org",
"doi.org",
"biorxiv.org",
"journals.sfu.ca",
"aclanthology.org",
"tandfonline.com",
"joiv.org",
"f-droid.org",
".sciencedirect.com",
"featureassets.org",
"flowchart.js.org",
"lib.iitta.gov.ua",
"papers.ssrn.com",
"journals.aom.org",
"publica.fraunhofer.de",
"dam-oclc.bac-lac.gc.ca",
"fmv.nau.edu.ua",
"mocom.xmu.edu.cn",
"physics.brown.edu",
"isprs-archives.copernicus.org",
"cse.unsw.edu.au",
"irojournals.com",
"drpress.org",
"digitalcommons.memphis.edu",
"chemrxiv.org",
".azure.com",
".mlr-org.com",
"repository.ubn.ru.nl",
"dspace.aztidata.es",
"efmaefm.org",
"ddkang.github.io",
"ojs.lib.unideb.hu",
"ngcc.cn",
"gtg.webhost.uoradea.ro",
"ojs.sgsci.org",
"epub.ub.uni-greifswald.de",
"shubhanshu.com",
"b-cubed.eu",
"docs.geetest.com",
"annualreviews.org",
"repositorio.uteq.edu.ec",
"researchportal.bath.ac.uk",
"digitalscholarship.unlv.edu",
"aanda.org",
"utpjournals.press",
"repository.universitasbumigora.ac.id",
"cambridge.org",
"frida.re",
"eprints.cihanuniversity.edu.iq",
"amt.copernicus.org",
"zz.bdstatic.com",
".cloudfront.net",
"geodetski-vestnik.com",
".cdn-go.cn",
"mce.biophys.msu.ru",
"ee.cuhk.edu.hk",
"cs.ucy.ac.cy",
".deno.com",
"jil.go.jp",
"researchgate.net",
"adgeo.copernicus.org",
"files.eric.ed.gov",
"infoscience.epfl.ch",
"eartharxiv.org",
".itch.io",
".nih.gov",
"library.imaging.org",
"research-portal.uu.nl",
"awesome-poetry.top",
"indico.ifj.edu.pl",
".rust-lang.org",
"tools.strongvpn.asia",
"degruyter.com",
"library.wur.nl",
"3.8.6.95",
"rodconnolly.com",
".springernature.com",
"aloki.hu",
"ajol.info",
"researchonline.ljmu.ac.uk",
"rubytec.eu",
"article.stmacademicwriting.com",
".dkut.ac.ke",
"ere.ac.cn",
"ellenhamaker.github.io",
"newjaigs.com",
".clemson.edu",
"vbn.aau.dk",
"kyushu-u.elsevierpure.com",
"vite.dev",
"dspace.bracu.ac.bd",
"stat.washington.edu",
"aaltodoc.aalto.fi",
"idus.us.es",
".music.126.net",
"img-prod-cms-rt-microsoft-com.akamaized.net",
"ascopubs.org",
"jmes.humg.edu.vn",
"analises-ecologicas.com",
"scholar.its.ac.id",
"semanticscholar.org",
"elgaronline.com",
".weixin.qq.com",
"arxiv.org",
"stacks.cdc.gov",
"staff.science.uu.nl",
"tauri.app",
"journals.lww.com",
".aliyun.com",
"semarakilmu.com.my",
"trid.trb.org",
"iris.unipa.it",
"kosovaanthropologica.com",
"aiej.org",
"www.52pojie.cn",
"zora.uzh.ch",
"projectpythia.org",
"api.taylorfrancis.com",
"scholarbank.nus.edu.sg",
"econtent.hogrefe.com",
"cogvis.icaci.org",
"ojs.unud.ac.id",
"api.altmetric.com",
"ecosimpro.com",
"geography.ryerson.ca",
"cerf.radiologie.fr",
"norma.ncirl.ie",
"digitalcommons.usu.edu",
"cp.copernicus.org",
"iris.unitn.it",
"enos.itcollege.ee",
"rigeo.org",
"acikerisim.uludag.edu.tr",
".mdpi-res.com",
"rss.onlinelibrary.wiley.com",
"jove.com",
".readthedocs.io",
"openproceedings.org",
"data.ornldaac.earthdata.nasa.gov",
"people.cs.uct.ac.za",
"repository.law.indiana.edu",
"journals.openedition.org",
"ij-aquaticbiology.com",
"diva-portal.org",
"ntut.elsevierpure.com",
"tobaccocontrol.bmj.com",
"research.ed.ac.uk",
"indianjournals.com",
".usgs.gov",
"scielo.org.za",
".epfl.ch",
"brill.com",
"journals.uchicago.edu",
"journals.sagepub.com",
"repository.gatech.edu",
"platform-api.sharethis.com",
"scis.scichina.com",
"scijournals.onlinelibrary.wiley.com",
"theses.hal.science",
"aka.ms",
"int-res.com",
" fourier.taobao.com",
"pubs.rsna.org",
"orbilu.uni.lu",
".openai.com",
"isip.piconepress.com",
"examples.rpkg.net",
"swdzgcdz.com",
"nature.com",
"lgincdnvzeuno.azureedge.net",
"softcomputing.net",
"journalskuwait.org",
"webofscience.com",
".jquery.com",
"felipebravom.com",
"currentprotocols.onlinelibrary.wiley.com",
"cityterritoryarchitecture.springeropen.com",
"sciltp.com",
"ehp.niehs.nih.gov",
"dione.lib.unipi.gr",
"seaver-faculty.pepperdine.edu",
"flore.unifi.it",
"calhoun.nps.edu",
"datascienceassn.org",
"papers.phmsociety.org",
".berkeley.edu",
".sun.ac.za",
"bayesiancomputationbook.com",
"nber.org",
"sscdigitalstorytelling.pbworks.com",
"earthdoc.org",
"nph.onlinelibrary.wiley.com",
".alicdn.com",
".microsoft.com",
"statmath.wu.ac.at",
"iibajournal.org",
".strongtech.org",
"www.wjx.cn",
".deno.dev",
"ica-abs.copernicus.org",
"open.library.ubc.ca",
"sci2s.ugr.es",
"is.ocha.ac.jp",
"dea.lib.unideb.hu",
"hal.science",
"docs.neu.edu.tr",
"ziglang.org",
"ojs.library.queensu.ca",
"www2.papelesdelpsicologo.es",
"pubsonline.informs.org",
"journals.um.si",
"iris.uniroma1.it",
"www5.informatik.uni-erlangen.de",
"researchportal.hw.ac.uk",
"benthamdirect.com",
"repository.lboro.ac.uk",
"cad-journal.net",
"journal.lenterailmu.com",
"pubs.aip.org",
"forestchemicalsreview.com",
"repository.uin-malang.ac.id",
"ifej.sanru.ac.ir",
"inria.hal.science",
"seer.ufu.br",
"irbis-nbuv.gov.ua",
"k0d.cc",
"uknowledge.uky.edu",
"ietresearch.onlinelibrary.wiley.com",
".ku.edu",
"tspace.library.utoronto.ca",
"iaees.org",
"ijtech.eng.ui.ac.id",
"editor.md.ipandao.com",
"portlandpress.com",
"nuxt.com",
"docs-neteasecloudmusicapi.vercel.app",
"rshare.library.torontomu.ca",
"openaccess.city.ac.uk",
".hsforms.net",
"journals.flvc.org",
"xb.chinasmp.com",
"digitalcommons.calpoly.edu",
"yadda.icm.edu.pl",
"courses.cs.duke.edu",
"opus.bibliothek.uni-augsburg.de",
".gradle.org",
"jurnal.polsri.ac.id",
"captcha.gtimg.com",
"plausible.io",
"repositori.upf.edu",
"cs.columbia.edu",
"h2o-release.s3.amazonaws.com",
"ica-proc.copernicus.org",
"vtechworks.lib.vt.edu",
"cs.toronto.edu",
"apps.dtic.mil",
"aivc.org",
"xlescience.org",
"assets-eu.researchsquare.com",
"drops.dagstuhl.de",
"dataorigami.net",
"research.rug.nl",
"kaggle.com",
"gee-community-catalog.org",
"ajemb.us",
"eprints.umsida.ac.id",
"knowledgewords.com",
"journals2.ums.ac.id",
"sto.nato.int",
"journals.asm.org",
"scielo.br",
"eprints.gla.ac.uk",
"meetingorganizer.copernicus.org",
"bpspsychub.onlinelibrary.wiley.com",
"epjdatascience.springeropen.com",
"ijcs.net",
"alvinang.sg",
"cal-tek.eu",
"isprs-annals.copernicus.org",
"biomedicaljour.com",
"dl.gi.de",
"waseda.elsevierpure.com",
"ise.ncsu.edu",
"ijmge.ut.ac.ir",
"machineintelligenceresearchs.com",
"sure.sunderland.ac.uk",
".biomedcentral.com",
"mediatum.ub.tum.de",
"airitilibrary.com",
"scholarworks.iupui.edu",
"jscholarship.library.jhu.edu",
".captcha.qq.com",
".oracle.com",
"jutif.if.unsoed.ac.id",
"rotman-baycrest.on.ca",
"wandoujia.com",
".journal-grail.science",
"vldb.org",
"cje.net.cn",
"shizuku.rikka.app",
"go.gale.com",
"doc.ic.ac.uk",
".codabench.org",
"scholarworks.umt.edu",
".sciencedirectassets.com",
"g.3gl.net",
"nsojournals.onlinelibrary.wiley.com",
"jgit.kntu.ac.ir",
"faculty.educ.ubc.ca",
"yuque.com",
"lifescied.org",
"diglib.eg.org",
"krex.k-state.edu",
"jsj.top",
"eprints.soton.ac.uk",
"holoviews.org",
"journal.genintelektual.id",
"medrxiv.org",
".nasa.gov",
"dipterajournal.com",
"mdag.com",
"eneuro.org",
"ajph.aphapublications.org",
"proceedings.neurips.cc",
".psu.edu",
"www2.jpgu.org",
"elibrary.ru",
"wps.com",
"biomisa.org",
"taylorfrancis.com",
"pure.mpg.de",
"figshare.com",
"github.com",
"vis.cs.ucdavis.edu",
".arxiv.org",
"scholar.smu.edu",
"ashpublications.org",
"journal.admi.or.id",
"spatial.usc.edu",
"trisala.salatiga.go.id",
"jmis.org",
".hanspub.org",
".audacityteam.org",
"library.seg.org",
"spiedigitallibrary.org",
"iccgis2018.cartography-gis.com",
"openresearchsoftware.metajnl.com",
"revistafesahancccal.org",
"esploro.libs.uga.edu",
"osti.gov",
"docs.lib.purdue.edu",
"bright-journal.org",
"icevirtuallibrary.com",
"socialwork.wayne.edu",
"badge.dimensions.ai",
"tidsskrift.dk",
"dovepress.com",
"scholarpedia.org",
"dspace.library.uvic.ca",
"caislab.kaist.ac.kr",
"prodregistryv2.org",
"jstatsoft.org",
"cgspace.cgiar.org",
"browser-intake-datadoghq.com",
"frankxue.com",
"ejournal.seaninstitute.or.id",
"muse.jhu.edu",
".readthedocs.org",
"ojs.unikom.ac.id",
"aaai.org",
"oup.silverchair-cdn.com",
"ant.design",
"zslpublications.onlinelibrary.wiley.com",
"naec.org.uk",
"deepdownstudios.com",
"sbleis.ch",
"direct.mit.edu",
"journals.plos.org",
"research-repository.griffith.edu.au",
"keras.io",
"genome.cshlp.org",
"ahajournals.org",
"journal.r-project.org",
"repository.lsu.edu",
"ijmh.org",
"cmake.org",
"webextension.org",
"www1.cs.columbia.edu",
"jlc.jst.go.jp",
"icaci.org",
"unitec.ac.nz",
"proceedings.esri.com",
"geospatialhealth.net",
".yeepay.com",
"e-tarjome.com",
"elea.unisa.it",
"humanit.hb.se",
".microsoftonline.com",
"mdpi.com",
"repository.isls.org",
".wpscdn.com",
"giirj.com",
"pages.cs.wisc.edu",
"repository.arizona.edu",
"apsjournals.apsnet.org",
"journal.stekom.ac.id",
"journalinstal.cattleyadf.org",
"ijiset.com",
"sciendo.com",
"epstem.net",
"ageconsearch.umn.edu",
"digital.wpi.edu",
"mednexus.org",
"esajournals.onlinelibrary.wiley.com",
"ascelibrary.org",
"joss.theoj.org",
"repositorio.unesp.br",
"novami.com",
"ir.uitm.edu.my",
"ntrs.nasa.gov",
"report.qqweb.qq.com",
"aapm.onlinelibrary.wiley.com",
"ojs.aaai.org",
"kb.osu.edu",
"scrapy.org",
"sci-hub.gg",
"w3.mi.parisdescartes.fr",
".office.com",
"ceeol.com",
"aitskadapa.ac.in",
"hrcak.srce.hr",
"jmlr.org",
"ijcst.journals.yorku.ca",
"pressto.amu.edu.pl",
".gongkaoshequ.com",
"nora.nerc.ac.uk",
"zlxb.zafu.edu.cn",
"vinar.vin.bg.ac.rs",
"royalsocietypublishing.org",
"pytorch.org",
"catsr.vse.gmu.edu",
"osf.io",
"discovery.ucl.ac.uk",
"informatica.si",
"hal-ciheam.iamm.fr",
".alipayobjects.com",
"ajce.aut.ac.ir",
"michaelfullan.ca",
".adobedtm.com",
"scholar.archive.org",
"lib.unib.ac.id",
"httpbin.org",
"jmirs.org",
"bioone.org",
"cris.bgu.ac.il",
"boa.unimib.it",
"irjaes.com",
".alipay.com",
"openai.com",
".lzu.edu.cn",
"10.10.0.166",
"escholarship.org",
"aisel.aisnet.org",
".biologists.com",
"dspace.mit.edu",
"cyxb.magtech.com.cn",
"cit.ctu.edu.vn",
"jonathansarwono.info",
"cs.cmu.edu",
"ijadis.org",
"is.muni.cz",
"uge-share.science.upjs.sk",
"eprints.lse.ac.uk",
"conbio.onlinelibrary.wiley.com",
"gitlab.com",
"zenodo.org",
"kims-imio.kz",
".graph.qq.com",
"swsc-journal.org",
"deepblue.lib.umich.edu",
"ajnr.org",
"studiostaticassetsprod.azureedge.net",
".126.net",
"luminati.io",
"bdtd.ibict.br",
"pdfs.semanticscholar.org",
".esri.com",
".amap.com",
"angeo.copernicus.org",
"jinav.org",
"soil.copernicus.org",
"ceur-ws.org",
"vipsi.org",
"arc.aiaa.org",
"designsociety.org",
"scholar.lib.ntnu.edu.tw",
"digitalcommons.buffalostate.edu",
".allenpress.com",
"techrxiv.org",
"gitlab.jsc.fz-juelich.de",
"e-jwj.org",
".theoj.org",
"ssl.ptlogin2.graph.qq.com",
".nature.com",
"jau.vgtu.lt",
"kiss.kstudy.com",
",.cnzz.com",
"ruor.uottawa.ca",
"mhealth.jmir.org",
"researchportal.port.ac.uk",
"shs.hal.science",
"reproducible-builds.org",
"xarray.dev",
"iocscience.org",
"natuurtijdschriften.nl",
"staff.fnwi.uva.nl",
"seamlessaccess.org",
"fardapaper.ir",
"joig.net",
"ieee-ims.org",
"tianditu.gov.cn",
"proceedings.mlr.press",
"scirp.org",
"sk.sagepub.com",
"etda.libraries.psu.edu",
".kaggle.io",
"peerj.com",
"vizml.media.mit.edu",
"int-arch-photogramm-remote-sens-spatial-inf-sci.net",
".pymc.io",
".simpleanalyticscdn.com",
".sonaliyadav.workers.dev",
"igi-global.com",
"ir.lib.uwo.ca",
"scpe.org",
"tensorflow.org",
"jidt.org",
"airccj.org",
"academicjournals.org",
"sendimage.whu.edu.cn",
"tristan.cordier.free.fr",
"journal.neolectura.com",
".holoviz.org",
"isas.org.in",
"fjs.fudutsinma.edu.ng",
"pydub.com",
"deno.com",
"cs.cornell.edu",
"adsabs.harvard.edu",
"people.csail.mit.edu",
"localhost",
"air.ashesi.edu.gh",
"researchsquare.com",
"bit.ly",
"fondazionemcr.it",
"upcommons.upc.edu",
".hubspot.com",
"aas.net.cn",
"digital-library.theiet.org",
"acrjournals.onlinelibrary.wiley.com",
".qt.io",
"syxb-cps.com.cn",
"openaging.com",
"agritrop.cirad.fr",
".uclouvain.be",
"philstat.org",
".rsc.org",
"peer.asee.org",
"deeplearning.ir",
"journal.psych.ac.cn",
"digibug.ugr.es",
"alipayobjects.com",
"learningsys.org",
"cirlmemphis.com",
".r-project.org",
"liverpooluniversitypress.co.uk",
".cambridge.org",
"mercurial-scm.org",
".unl.edu",
"content.iospress.com",
"climatechange.ai",
"developer.android.com",
"sisis.rz.htw-berlin.de",
"journals.riverpublishers.com",
"erepository.uonbi.ac.ke",
".qutebrowser.org",
"nanobe.org",
"microbiologyresearch.org",
"hackveda.in",
"setac.onlinelibrary.wiley.com",
"worldclim.org",
"nyaspubs.onlinelibrary.wiley.com",
"caffeineviking.net",
"revues.imist.ma",
"gbpihed.gov.in",
"res.wx.qq.com",
"revistas.ucc.edu.co",
"nowpublishers.com",
"projecteuclid.org",
"journal.lu.lv",
"js.trendmd.com",
"uwe-repository.worktribe.com",
"eprints.utm.my",
"fonts.gstatic.com",
"cathi.uacj.mx",
"jstnar.iut.ac.ir",
"figshare.utas.edu.au",
"e3s-conferences.org",
"ejournal.undip.ac.id",
"researchplusjournal.com",
"mesopotamian.press",
"witpress.com",
"ora.ox.ac.uk",
"changfengbox.top",
"computer.org",
"anapub.co.ke",
"pages.charlotte.edu",
"oa.upm.es",
"ojs.bonviewpress.com",
"analyticalsciencejournals.onlinelibrary.wiley.com",
"science.org",
"web.pdx.edu",
".privado.ai",
"qmro.qmul.ac.uk",
"dergipark.org.tr",
"compass.onlinelibrary.wiley.com",
"scholarworks.gsu.edu",
"ssoar.info",
"perpustakaan.atmaluhur.ac.id",
"jamanetwork.com",
"rgs-ibg.onlinelibrary.wiley.com",
"ir.library.oregonstate.edu",
"gdal.org",
"cdigital.uv.mx",
"dlib.hust.edu.vn",
".strongvpn.com",
"jait.us",
".github.com",
".kaggleusercontent.com",
"sf-conference.eu",
"search.ieice.org",
"pubs.usgs.gov",
"core.ac.uk",
"mtkxjs.com.cn",
"journals.ashs.org",
"nhess.copernicus.org",
"wfs.swst.org",
"eurasianpublications.com",
"frontiersin.org",
"cse.iitkgp.ac.in",
"helda.helsinki.fi",
"jurnal.likmi.ac.id",
"dline.info",
"cdnsciencepub.com",
"aacrjournals.org",
"escholarship.mcgill.ca",
"mc-stan.org",
"archive.interconf.center",
"agsjournals.onlinelibrary.wiley.com",
"jmir.org",
"jmg.bmj.com",
"scielo.org.mx",
"oneecosystem.pensoft.net",
"kar.kent.ac.uk",
"europepmc.org",
".newrelic.com",
"academic-pub.org",
"oaepublish.com",
"dialnet.unirioja.es",
"hlevkin.com",
"lit2talks.com",
"rmets.onlinelibrary.wiley.com",
"docs.huihoo.com",
"files.sisclima.it",
"opg.optica.org",
"journal.cartography.or.kr",
"graph.qq.com",
"journal.dcs.or.kr",
"meridian.allenpress.com",
"fonts.loli.net",
".mmstat.com",
"sp0.baidu.com",
"smujo.id",
"nmbu.brage.unit.no",
"hcjournal.org",
"incaindia.org",
"croris.hr",
"mail.qq.com",
"dl.acm.org",
"reactnative.cn",
"research.aalto.fi",
"ieeexplore.ieee.org",
"digitalcommons.library.umaine.edu",
"reprints.gravitywaves.com",
"repository.unika.ac.id",
"cummings-lab.org",
"policycommons.net",
"jacc.org",
"littlefreedigitallibrary.com",
"ijlaitse.com",
"wins.or.kr",
".ssrn.com",
"apiacoa.org",
"jsod-cieo.net",
"ncbi.nlm.nih.gov",
"real.mtak.hu",
"eprints.fri.uni-lj.si",
"library-archives.canada.ca",
"tvst.arvojournals.org",
"cir.nii.ac.jp",
"rbciamb.com.br",
"ffmpeg.org",
"repository.iep.bg.ac.rs",
"mae.ucf.edu",
"gfzpublic.gfz-potsdam.de",
"staff.icar.cnr.it",
"connormwood.com",
".springer.com",
"stats.ox.ac.uk",
"matplotlib.org",
"yandy-ager.com",
"inis.iaea.org",
".posit.co",
".scienceconnect.io",
"philarchive.org",
"hdsr.mitpress.mit.edu",
"iaeng.org",
"knowledgecenter.ubt-uni.net",
"iopscience.iop.org",
"keep.lib.asu.edu",
"puiij.com",
"dr.ntu.edu.sg",
"conference.sdo.esoc.esa.int",
"physicamedica.com",
"playwright.dev",
"eprint.iacr.org",
"dada.cs.washington.edu",
"bakerlab.org",
"koreascience.kr",
"cair.org",
".wandoujia.com",
"ueaeprints.uea.ac.uk",
"eprints.qut.edu.au",
"cartographicperspectives.org",
"reabic.net",
"ejournal.stiepena.ac.id",
"cyberleninka.ru",
"orbi.uliege.be",
"rosap.ntl.bts.gov",
"guilfordjournals.com",
"ecmlpkdd2017.ijs.si",
"ascpt.onlinelibrary.wiley.com",
"tallinzen.net",
"academic.oup.com",
"edepot.wur.nl",
"essopenarchive.org",
".neea.edu.cn",
"jos.unsoed.ac.id",
"lup.lub.lu.se",
"getd.libs.uga.edu",
"www2.eecs.berkeley.edu",
"iwaponline.com",
"humanfactors.jmir.org",
".aegis.qq.com",
".tensorflow.org",
"wiley.com",
"kimi.com",
".jinshujucdn.com",
"kharazmi-statistics.ir",
"formative.jmir.org",
"atlantis-press.com",
"icai.ektf.hu",
"digital.library.txstate.edu",
"cs.tufts.edu",
"easy.dans.knaw.nl",
"asmedc.silverchair-cdn.com",
"cdn.aaai.org",
"inderscienceonline.com",
"service.seamlessaccess.org",
"dl.begellhouse.com",
"github.githubassets.com",
"daac.ornl.gov",
"repositorio.ipcb.pt",
"personales.upv.es",
"popcenter.asu.edu",
".mail.qq.com",
"sentic.net",
".mlr.press",
"users.eecs.northwestern.edu",
"jamris.org",
"proceedings.stis.ac.id",
"hm.baidu.com",
"lyellcollection.org",
"ias.ac.in",
"bera-journals.onlinelibrary.wiley.com",
"dsr.inpe.br",
"scholarworks.alaska.edu",
"thelancet.com",
"gmd.copernicus.org",
"journals.co.za",
"106.54.215.74",
"journals.library.ualberta.ca",
"research-collection.ethz.ch",
"educationaldatamining.org",
".jinshujufiles.com",
"thilowellmann.de",
"bam.nr-data.net",
".gyan.dev",
"vestnikskfu.elpub.ru",
"biodiversity-science.net",
"nasm.us",
"selenium.dev",
"ecoagri.ac.cn",
"assets.pubpub.org",
"acsess.onlinelibrary.wiley.com",
"asprs.org",
"arlis.org",
"imis.uni-luebeck.de",
"music.163.com",
".ucdl.pp.uc.cn",
"worldscientific.com",
"mcponline.org",
"git-scm.com",
"repositorio.ufsc.br",
"scientific.net",
"asmedigitalcollection.asme.org",
"stars.library.ucf.edu",
"zotero.org",
"predictive-workshop.github.io",
"pubs.acs.org",
"ijlter.org",
"pgmpy.org",
"cse512-15s.github.io",
"btstu.researchcommons.org",
"ejmste.com",
"burjcdigital.urjc.es",
"nejm.org",
"meeting.qq.com",
"strongvpn.com",
".s3.amazonaws.com",
"redux.js.org",
"analytics.ng",
".clarivate.com",
"spandidos-publications.com",
"digital.lib.washington.edu",
"davis-group-quantum-matter-research.ie",
"datajobs.com",
"nwr.gov.cn",
"durham-repository.worktribe.com",
"ideapublishers.org",
"eric.ed.gov",
"viz.icaci.org",
"web2py.iiit.ac.in",
"icaarconcrete.org",
"research.utwente.nl",
"studenttheses.uu.nl",
"seas.upenn.edu",
".kaggle.com",
"msftconnecttest.com",
"ink.library.smu.edu.sg",
"iipseries.org",
"publishup.uni-potsdam.de",
"era.library.ualberta.ca",
"distill.pub",
"search.ebscohost.com",
".aligames.com",
"4spepublications.onlinelibrary.wiley.com",
"bsppjournals.onlinelibrary.wiley.com",
"wikiworkshop.org",
"heinonline.org",
"ui.adsabs.harvard.edu",
"journals.ametsoc.org",
"esann.org",
".ansfoundation.org",
"gcdz.org",
"cbml.science",
"kresttechnology.com",
"bib.irb.hr",
"jcrinn.com",
"sidalc.net",
"marginaleffects.com",
"jurnal.yoctobrain.org",
"logic.pdmi.ras.ru",
"numfocus.org",
"medicinskiglasnik.ba",
"cv-foundation.org",
"idl.iscram.org",
"apktool.org",
"repository.fit.edu",
"bigr.io",
"ri.conicet.gov.ar",
"library.oapen.org",
"ams.confex.com",
"pypi.org",
"journal.iba-suk.edu.pk",
"karger.com",
"journals.physiology.org",
"publish.csiro.au",
"agile-giss.copernicus.org",
"electronjs.org",
".163.com",
"bura.brunel.ac.uk",
"nodejs.org",
".riskified.com",
"elib.dlr.de",
".xarray.dev",
"djournals.com",
"iase-web.org",
".nvidia.com",
"cabidigitallibrary.org",
"cdn.techscience.cn",
"ecology.ghislainv.fr",
"dash.harvard.edu",
"ofai.at",
"personality-project.org",
"essd.copernicus.org",
"ebooks.iospress.nl",
"gisak.vsb.cz",
"iovs.arvojournals.org",
"etd.ohiolink.edu",
"tore.tuhh.de",
"alipay.com",
"eltikom.poliban.ac.id",
"scipost.org",
".kde.org",
".githubusercontent.com",
"klein.mit.edu",
"engrxiv.org",
".ieee.org",
"isca-archive.org",
"file.fouladi.ir",
"periodicos.ufpe.br",
"bibliotekanauki.pl",
"intereuroconf.com",
"bme.ufl.edu",
"tethys.pnl.gov",
"politesi.polimi.it",
".typekit.net",
"jurnal.polinema.ac.id",
"repository.library.noaa.gov",
"jov.arvojournals.org",
"tqmp.org",
"telkomnika.uad.ac.id",
"npg.copernicus.org",
"ijme.mui.ac.ir",
"orcid.org",
"citeseerx.ist.psu.edu",
"cse.fau.edu",
"journals.vilniustech.lt",
"lavaan.org",
".els-cdn.com",
"experts.umn.edu",
"arcgis.com",
"philsci-archive.pitt.edu",
"thuvienso.hoasen.edu.vn",
"apsnet.org",
"terradigitalis.igg.unam.mx",
"webofknowledge.com",
".r-lib.org",
"gato-docs.its.txstate.edu",
"igj-iraq.org",
"bmj.com",
"sciopen.com",
"fs.usda.gov",
"jastt.org",
".netzel.pl",
"cdn.isr.umich.edu",
"jneurosci.org",
"nrl.northumbria.ac.uk",
".oaistatic.com",
"openjournals.uwaterloo.ca",
"duo.uio.no",
"doria.fi",
"cje.ustb.edu.cn",
"bmjopen.bmj.com",
"pascal-francis.inist.fr",
"authorea.com",
"minesparis-psl.hal.science",
"www-ai.ijs.si",
"researchnow.flinders.edu.au",
"ideals.illinois.edu",
"statmodeling.stat.columbia.edu",
"qzapp.qlogo.cn",
"pptr.dev",
".sams-sigma.com",
"xai-tools.drwhy.ai",
"dalex.drwhy.ai",
"mathematics.foi.hr",
"ema.drwhy.ai",
"staff.fmi.uvt.ro",
"paulbuerkner.com",
"igraph.org",
"lavaan.ugent.be",
"ggforce.data-imaginist.com",
"raw.githack.com",
".ptlogin2.qq.com",
"fellenius.net",
"ocgy.ubc.ca",
"r.igraph.org",
"wilkelab.org",
"ggraph.data-imaginist.com",
"pmc.ncbi.nlm.nih.gov",
"d-nb.info",
"mermaidchart.com",
"graphviz.org",
"gisinternals.com",
"anaconda.org",
"docs.conda.io",
"mirrors.tuna.tsinghua.edu.cn",
"mirrors.ustc.edu.cn",
"tracker.debian.org",
"packages.fedoraproject.org",
"pkgs.alpinelinux.org",
"lfd.uci.edu",
"diagrams.mingrammer.com",
"builds.libav.org",
"zwang4.github.io",
"cartogis.org",
"typora.io",
"geoanalytics.net",
"obsidian.md",
"mermaid.live",
"researchjournalnmit.wordpress.com",
"publikationen.ub.uni-frankfurt.de",
".sinaimg.cn",
"elifesciences.org",
"springer.com",
".cgiar.org",
"s.gravatar.com",
"tensorflow-dot-devsite-v2-prod-3p.appspot.com",
"centaur.reading.ac.uk",
"scraperapi.com",
"allenai.org",
"psysci.org",
"anatomypubs.onlinelibrary.wiley.com",
"pqm.unibe.ch",
"disi.unitn.it",
"journals.humankinetics.com",
"synapse.koreamed.org",
"redux-toolkit.js.org",
"journal-dogorangsang.in",
"geochina.cgs.gov.cn",
"enviromicro-journals.onlinelibrary.wiley.com",
"digitalcommons.library.tmc.edu",
"psycnet.apa.org",
"scihorizon.com",
"beei.org",
"journal.rescollacomm.com",
"ion.org",
".cloudflareinsights.com",
"jmasm.com",
".researchcommons.org",
"journal.code4lib.org",
"acnsci.org",
".live.com",
"ojs.cvut.cz",
"kops.uni-konstanz.de",
"journals.healio.com",
"ch.whu.edu.cn",
"react-redux.js.org",
"scitepress.org",
"ntnuopen.ntnu.no",
"llvm.org",
"ejournal.unma.ac.id",
"prism.ucalgary.ca",
"lmb.informatik.uni-freiburg.de",
"bodden.de",
"usenix.org",
"dev.icaci.org",
"erj.ersjournals.com",
"jstor.org",
"matec-conferences.org",
"jstage.jst.go.jp",
"ecoevorxiv.org",
"canteach.candu.org",
"preprints.org",
"etamaths.com",
"muroran-it.repo.nii.ac.jp",
"mljar.com",
".msftconnecttest.com",
"nuriaoliver.com",
".siam.org",
"tobias-lib.ub.uni-tuebingen.de",
".informs.org",
"ieeeprojects.eminents.in",
".osgeo.org",
"resjournals.onlinelibrary.wiley.com",
"aeaweb.org",
"archium.ateneo.edu",
"brgm.hal.science",
"coursesteach.com",
"par.nsf.gov",
".jsdelivr.net",
"aegis.qq.com",
"agupubs.onlinelibrary.wiley.com",
"alz-journals.onlinelibrary.wiley.com",
"ijsdcs.com",
"iasj.net",
".qqmail.com",
"mavmatrix.uta.edu",
"adac.ee",
"live.com",
"torrossa.com",
"msys2.org",
"lib.baomitu.com",
"infeb.org",
"idpublications.org",
"embopress.org",
"chatgpt.com",
"ira.lib.polyu.edu.hk",
".apta.gov.cn",
"lexjansen.com",
".gstatic.com",
".iopscience.com",
"researchcommons.waikato.ac.nz",
".office.net",
"acikerisim.fsm.edu.tr",
"dusk.geo.orst.edu",
"s3.ca-central-1.amazonaws.com",
"philpapers.org",
"office.sjas-journal.org",
"wires.onlinelibrary.wiley.com",
".doi.org",
".acm.org",
"f1000research.com",
"search.proquest.com",
"archive.ismrm.org",
"josis.org",
"repository.kaust.edu.sa",
"research.tue.nl",
"elib.psu.by",
"aab.copernicus.org",
"petsymposium.org",
".elsevier.com",
"yangli-feasibility.com",
"keevin60907.github.io",
"dora.lib4ri.ch",
"ece.neu.edu",
"academicradiology.org",
"41.59.85.213",
"ws",
"logincdn.msauth.net",
".azureedge.net",
"pnas.org",
"scipy.org",
"acp.copernicus.org",
"alyssax.com",
"dlsu.edu.ph",
"onlinelibrary.wiley.com",
"academia.edu",
"amostech.com",
"lalavision.com",
"api.crossref.org",
"pandas.pydata.org",
"js.zi-scripts.com",
".yale.edu",
"back.nber.org",
"static.hotjar.com",
".sciendo.com",
"pubhort.org",
"jabfm.org",
"papers.neurips.cc",
".ufrpe.br",
"sidalc.net",
"people.clas.ufl.edu",
"leg.ufpr.br",
".addthis.com",
"static.ithaka.org",

      };

      // 获取 URL 的主机名
      const std::string host = url.host();
      bool is_allowed = false;

      // 遍历允许的主机名列表
      for (size_t i = 0; i < std::size(kAllowedHosts); ++i) {
          // 检查是否匹配允许的后缀或完全匹配
          if ((kAllowedHosts[i][0] == '.' && base::EndsWith(host, kAllowedHosts[i], base::CompareCase::INSENSITIVE_ASCII)) ||
              host == kAllowedHosts[i]) {
              is_allowed = true;
              break;
          }
      }

      // 如果不在允许列表中，拦截请求
      if (!is_allowed) {
          LOG(ERROR) << "Block URL in URLRequest: " << url;
          url_chain_[0] = GURL(url::kTraceScheme + (":" + url.possibly_invalid_spec()));
      }
  }

  context->url_requests()->insert(this);
  net_log_.BeginEvent(NetLogEventType::REQUEST_ALIVE, [&] {
    return NetLogURLRequestConstructorParams(url, priority_,
                                             traffic_annotation_);
  });
}

void URLRequest::BeforeRequestComplete(int error) {
  DCHECK(!job_.get());
  DCHECK_NE(ERR_IO_PENDING, error);

  // Check that there are no callbacks to already failed or canceled requests.
  DCHECK(!failed());

  OnCallToDelegateComplete();

  if (error != OK) {
    net_log_.AddEventWithStringParams(NetLogEventType::CANCELLED, "source",
                                      "delegate");
    StartJob(std::make_unique<URLRequestErrorJob>(this, error));
  } else if (!delegate_redirect_url_.is_empty()) {
    GURL new_url;
    new_url.Swap(&delegate_redirect_url_);

    StartJob(std::make_unique<URLRequestRedirectJob>(
        this, new_url,
        // Use status code 307 to preserve the method, so POST requests work.
        RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT,
        "Delegate"));
  } else {
    StartJob(context_->job_factory()->CreateJob(this));
  }
}

void URLRequest::StartJob(std::unique_ptr<URLRequestJob> job) {
  DCHECK(!is_pending_);
  DCHECK(!job_);
  if (is_created_from_network_anonymization_key_) {
    DCHECK(load_flags() & LOAD_DISABLE_CACHE);
    DCHECK(!allow_credentials_);
  }

  net_log_.BeginEvent(NetLogEventType::URL_REQUEST_START_JOB, [&] {
    return NetLogURLRequestStartParams(
        url(), method_, load_flags(), isolation_info_, site_for_cookies_,
        initiator_,
        upload_data_stream_ ? upload_data_stream_->identifier() : -1);
  });

  job_ = std::move(job);
  job_->SetExtraRequestHeaders(extra_request_headers_);
  job_->SetPriority(priority_);
  job_->SetRequestHeadersCallback(request_headers_callback_);
  job_->SetEarlyResponseHeadersCallback(early_response_headers_callback_);
  if (is_shared_dictionary_read_allowed_callback_) {
    job_->SetIsSharedDictionaryReadAllowedCallback(
        is_shared_dictionary_read_allowed_callback_);
  }
  job_->SetResponseHeadersCallback(response_headers_callback_);
  if (shared_dictionary_getter_) {
    job_->SetSharedDictionaryGetter(shared_dictionary_getter_);
  }

  if (upload_data_stream_.get())
    job_->SetUpload(upload_data_stream_.get());

  is_pending_ = true;
  is_redirecting_ = false;
  deferred_redirect_info_.reset();

  response_info_.was_cached = false;

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  GURL referrer_url(referrer_);
  bool same_origin_for_metrics;

  if (referrer_url !=
      URLRequestJob::ComputeReferrerForPolicy(
          referrer_policy_, referrer_url, url(), &same_origin_for_metrics)) {
    if (!network_delegate() ||
        !network_delegate()->CancelURLRequestWithPolicyViolatingReferrerHeader(
            *this, url(), referrer_url)) {
      referrer_.clear();
    } else {
      // We need to clear the referrer anyway to avoid an infinite recursion
      // when starting the error job.
      referrer_.clear();
      net_log_.AddEventWithStringParams(NetLogEventType::CANCELLED, "source",
                                        "delegate");
      RestartWithJob(
          std::make_unique<URLRequestErrorJob>(this, ERR_BLOCKED_BY_CLIENT));
      return;
    }
  }

  RecordReferrerGranularityMetrics(same_origin_for_metrics);

  // Start() always completes asynchronously.
  //
  // Status is generally set by URLRequestJob itself, but Start() calls
  // directly into the URLRequestJob subclass, so URLRequestJob can't set it
  // here.
  // TODO(mmenke):  Make the URLRequest manage its own status.
  status_ = ERR_IO_PENDING;
  job_->Start();
}

void URLRequest::RestartWithJob(std::unique_ptr<URLRequestJob> job) {
  DCHECK(job->request() == this);
  PrepareToRestart();
  StartJob(std::move(job));
}

int URLRequest::Cancel() {
  return DoCancel(ERR_ABORTED, SSLInfo());
}

int URLRequest::CancelWithError(int error) {
  return DoCancel(error, SSLInfo());
}

void URLRequest::CancelWithSSLError(int error, const SSLInfo& ssl_info) {
  // This should only be called on a started request.
  if (!is_pending_ || !job_.get() || job_->has_response_started()) {
    NOTREACHED_IN_MIGRATION();
    return;
  }
  DoCancel(error, ssl_info);
}

int URLRequest::DoCancel(int error, const SSLInfo& ssl_info) {
  DCHECK_LT(error, 0);
  // If cancelled while calling a delegate, clear delegate info.
  if (calling_delegate_) {
    LogUnblocked();
    OnCallToDelegateComplete();
  }

  // If the URL request already has an error status, then canceling is a no-op.
  // Plus, we don't want to change the error status once it has been set.
  if (!failed()) {
    status_ = error;
    response_info_.ssl_info = ssl_info;

    // If the request hasn't already been completed, log a cancellation event.
    if (!has_notified_completion_) {
      // Don't log an error code on ERR_ABORTED, since that's redundant.
      net_log_.AddEventWithNetErrorCode(NetLogEventType::CANCELLED,
                                        error == ERR_ABORTED ? OK : error);
    }
  }

  if (is_pending_ && job_.get())
    job_->Kill();

  // We need to notify about the end of this job here synchronously. The
  // Job sends an asynchronous notification but by the time this is processed,
  // our |context_| is NULL.
  NotifyRequestCompleted();

  // The Job will call our NotifyDone method asynchronously.  This is done so
  // that the Delegate implementation can call Cancel without having to worry
  // about being called recursively.

  return status_;
}

int URLRequest::Read(IOBuffer* dest, int dest_size) {
  DCHECK(job_.get());
  DCHECK_NE(ERR_IO_PENDING, status_);

  // If this is the first read, end the delegate call that may have started in
  // OnResponseStarted.
  OnCallToDelegateComplete();

  // If the request has failed, Read() will return actual network error code.
  if (status_ != OK)
    return status_;

  // This handles reads after the request already completed successfully.
  // TODO(ahendrickson): DCHECK() that it is not done after
  // http://crbug.com/115705 is fixed.
  if (job_->is_done())
    return status_;

  if (dest_size == 0) {
    // Caller is not too bright.  I guess we've done what they asked.
    return OK;
  }

  // Caller should provide a buffer.
  DCHECK(dest && dest->data());

  int rv = job_->Read(dest, dest_size);
  if (rv == ERR_IO_PENDING) {
    set_status(ERR_IO_PENDING);
  } else if (rv <= 0) {
    NotifyRequestCompleted();
  }

  // If rv is not 0 or actual bytes read, the status cannot be success.
  DCHECK(rv >= 0 || status_ != OK);
  return rv;
}

void URLRequest::set_status(int status) {
  DCHECK_LE(status, 0);
  DCHECK(!failed() || (status != OK && status != ERR_IO_PENDING));
  status_ = status;
}

bool URLRequest::failed() const {
  return (status_ != OK && status_ != ERR_IO_PENDING);
}

int URLRequest::NotifyConnected(const TransportInfo& info,
                                CompletionOnceCallback callback) {
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_CONNECTED);
  int result = delegate_->OnConnected(
      this, info,
      base::BindOnce(
          [](URLRequest* request, CompletionOnceCallback callback, int result) {
            request->OnCallToDelegateComplete(result);
            std::move(callback).Run(result);
          },
          this, std::move(callback)));
  if (result != ERR_IO_PENDING)
    OnCallToDelegateComplete(result);
  return result;
}

void URLRequest::ReceivedRedirect(RedirectInfo redirect_info) {
  DCHECK_EQ(OK, status_);
  is_redirecting_ = true;
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_RECEIVED_REDIRECT);

  // When notifying the URLRequest::Delegate, it can destroy the request,
  // which will destroy |this|.  After calling to the URLRequest::Delegate,
  // pointer must be checked to see if |this| still exists, and if not, the
  // code must return immediately.
  base::WeakPtr<URLRequest> weak_this(weak_factory_.GetWeakPtr());
  bool defer_redirect = false;
  delegate_->OnReceivedRedirect(this, redirect_info, &defer_redirect);

  // Ensure that the request wasn't detached, destroyed, or canceled in
  // NotifyReceivedRedirect.
  if (!weak_this || failed()) {
    return;
  }

  if (defer_redirect) {
    deferred_redirect_info_ = std::move(redirect_info);
  } else {
    Redirect(redirect_info, /*removed_headers=*/std::nullopt,
             /*modified_headers=*/std::nullopt);
  }
  // |this| may be have been destroyed here.
}

void URLRequest::NotifyResponseStarted(int net_error) {
  DCHECK_LE(net_error, 0);

  // Change status if there was an error.
  if (net_error != OK)
    set_status(net_error);

  // |status_| should not be ERR_IO_PENDING when calling into the
  // URLRequest::Delegate().
  DCHECK_NE(ERR_IO_PENDING, status_);

  net_log_.EndEventWithNetErrorCode(NetLogEventType::URL_REQUEST_START_JOB,
                                    net_error);

  // In some cases (e.g. an event was canceled), we might have sent the
  // completion event and receive a NotifyResponseStarted() later.
  if (!has_notified_completion_ && net_error == OK) {
    if (network_delegate())
      network_delegate()->NotifyResponseStarted(this, net_error);
  }

  // Notify in case the entire URL Request has been finished.
  if (!has_notified_completion_ && net_error != OK)
    NotifyRequestCompleted();

  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_RESPONSE_STARTED);
  delegate_->OnResponseStarted(this, net_error);
  // Nothing may appear below this line as OnResponseStarted may delete
  // |this|.
}

void URLRequest::FollowDeferredRedirect(
    const std::optional<std::vector<std::string>>& removed_headers,
    const std::optional<net::HttpRequestHeaders>& modified_headers) {
  DCHECK(job_.get());
  DCHECK_EQ(OK, status_);
  DCHECK(is_redirecting_);
  DCHECK(deferred_redirect_info_);

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  status_ = ERR_IO_PENDING;

  // While this move is not strictly needed, Redirect() will start a new Job,
  // which will delete `deferred_redirect_info_`. While `redirect_info` should
  // not be needed after it's been deleted, it's best to not have a reference to
  // a deleted object on the stack.
  RedirectInfo redirect_info = std::move(deferred_redirect_info_).value();

  Redirect(redirect_info, removed_headers, modified_headers);
}

void URLRequest::SetAuth(const AuthCredentials& credentials) {
  DCHECK(job_.get());
  DCHECK(job_->NeedsAuth());

  maybe_sent_cookies_.clear();
  maybe_stored_cookies_.clear();

  status_ = ERR_IO_PENDING;
  job_->SetAuth(credentials);
}

void URLRequest::CancelAuth() {
  DCHECK(job_.get());
  DCHECK(job_->NeedsAuth());

  status_ = ERR_IO_PENDING;
  job_->CancelAuth();
}

void URLRequest::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {
  DCHECK(job_.get());

  // Matches the call in NotifyCertificateRequested.
  OnCallToDelegateComplete();

  status_ = ERR_IO_PENDING;
  job_->ContinueWithCertificate(std::move(client_cert),
                                std::move(client_private_key));
}

void URLRequest::ContinueDespiteLastError() {
  DCHECK(job_.get());

  // Matches the call in NotifySSLCertificateError.
  OnCallToDelegateComplete();

  status_ = ERR_IO_PENDING;
  job_->ContinueDespiteLastError();
}

void URLRequest::AbortAndCloseConnection() {
  DCHECK_EQ(OK, status_);
  DCHECK(!has_notified_completion_);
  DCHECK(job_);
  job_->CloseConnectionOnDestruction();
  job_.reset();
}

void URLRequest::PrepareToRestart() {
  DCHECK(job_.get());

  // Close the current URL_REQUEST_START_JOB, since we will be starting a new
  // one.
  net_log_.EndEvent(NetLogEventType::URL_REQUEST_START_JOB);

  job_.reset();

  response_info_ = HttpResponseInfo();
  response_info_.request_time = base::Time::Now();

  load_timing_info_ = LoadTimingInfo();
  load_timing_info_.request_start_time = response_info_.request_time;
  load_timing_info_.request_start = base::TimeTicks::Now();

  status_ = OK;
  is_pending_ = false;
  proxy_chain_ = ProxyChain();
}

void URLRequest::Redirect(
    const RedirectInfo& redirect_info,
    const std::optional<std::vector<std::string>>& removed_headers,
    const std::optional<net::HttpRequestHeaders>& modified_headers) {
  // This method always succeeds. Whether |job_| is allowed to redirect to
  // |redirect_info| is checked in URLRequestJob::CanFollowRedirect, before
  // NotifyReceivedRedirect. This means the delegate can assume that, if it
  // accepted the redirect, future calls to OnResponseStarted correspond to
  // |redirect_info.new_url|.
  OnCallToDelegateComplete();
  if (net_log_.IsCapturing()) {
    net_log_.AddEventWithStringParams(
        NetLogEventType::URL_REQUEST_REDIRECTED, "location",
        redirect_info.new_url.possibly_invalid_spec());
  }

  if (network_delegate())
    network_delegate()->NotifyBeforeRedirect(this, redirect_info.new_url);

  if (!final_upload_progress_.position() && upload_data_stream_)
    final_upload_progress_ = upload_data_stream_->GetUploadProgress();
  PrepareToRestart();

  bool clear_body = false;
  net::RedirectUtil::UpdateHttpRequest(url(), method_, redirect_info,
                                       removed_headers, modified_headers,
                                       &extra_request_headers_, &clear_body);
  if (clear_body)
    upload_data_stream_.reset();

  method_ = redirect_info.new_method;
  referrer_ = redirect_info.new_referrer;
  referrer_policy_ = redirect_info.new_referrer_policy;
  site_for_cookies_ = redirect_info.new_site_for_cookies;
  set_isolation_info(isolation_info_.CreateForRedirect(
                         url::Origin::Create(redirect_info.new_url)),
                     redirect_info.new_url);

  cookie_setting_overrides().Remove(
      CookieSettingOverride::kStorageAccessGrantEligibleViaHeader);

  if ((load_flags() & LOAD_CAN_USE_SHARED_DICTIONARY) &&
      (load_flags() &
       LOAD_DISABLE_SHARED_DICTIONARY_AFTER_CROSS_ORIGIN_REDIRECT) &&
      !url::Origin::Create(url()).IsSameOriginWith(redirect_info.new_url)) {
    partial_load_flags_ &= ~LOAD_CAN_USE_SHARED_DICTIONARY;
  }

  url_chain_.push_back(redirect_info.new_url);
  --redirect_limit_;

  Start();
}

void URLRequest::RetryWithStorageAccess() {
  CHECK(!cookie_setting_overrides().Has(
      CookieSettingOverride::kStorageAccessGrantEligibleViaHeader));
  CHECK(!cookie_setting_overrides().Has(
      CookieSettingOverride::kStorageAccessGrantEligible));

  net_log_.AddEvent(NetLogEventType::URL_REQUEST_RETRY_WITH_STORAGE_ACCESS);
  if (network_delegate()) {
    network_delegate()->NotifyBeforeRetry(this);
  }

  cookie_setting_overrides().Put(
      CookieSettingOverride::kStorageAccessGrantEligibleViaHeader);
  set_storage_access_status(CalculateStorageAccessStatus());

  if (!final_upload_progress_.position() && upload_data_stream_) {
    final_upload_progress_ = upload_data_stream_->GetUploadProgress();
  }
  PrepareToRestart();

  // This isn't really a proper redirect, but we add to the `url_chain_` and
  // count it against the redirect limit anyway, to avoid unbounded retries.
  url_chain_.push_back(url());
  --redirect_limit_;

  Start();
}

// static
bool URLRequest::DefaultCanUseCookies() {
  return g_default_can_use_cookies;
}

const URLRequestContext* URLRequest::context() const {
  return context_;
}

NetworkDelegate* URLRequest::network_delegate() const {
  return context_->network_delegate();
}

int64_t URLRequest::GetExpectedContentSize() const {
  int64_t expected_content_size = -1;
  if (job_.get())
    expected_content_size = job_->expected_content_size();

  return expected_content_size;
}

void URLRequest::SetPriority(RequestPriority priority) {
  DCHECK_GE(priority, MINIMUM_PRIORITY);
  DCHECK_LE(priority, MAXIMUM_PRIORITY);

  if ((load_flags() & LOAD_IGNORE_LIMITS) && (priority != MAXIMUM_PRIORITY)) {
    NOTREACHED_IN_MIGRATION();
    // Maintain the invariant that requests with IGNORE_LIMITS set
    // have MAXIMUM_PRIORITY for release mode.
    return;
  }

  if (priority_ == priority)
    return;

  priority_ = priority;
  net_log_.AddEventWithStringParams(NetLogEventType::URL_REQUEST_SET_PRIORITY,
                                    "priority",
                                    RequestPriorityToString(priority_));
  if (job_.get())
    job_->SetPriority(priority_);
}

void URLRequest::SetPriorityIncremental(bool priority_incremental) {
  priority_incremental_ = priority_incremental;
}

void URLRequest::NotifyAuthRequired(
    std::unique_ptr<AuthChallengeInfo> auth_info) {
  DCHECK_EQ(OK, status_);
  DCHECK(auth_info);
  // Check that there are no callbacks to already failed or cancelled requests.
  DCHECK(!failed());

  delegate_->OnAuthRequired(this, *auth_info.get());
}

void URLRequest::NotifyCertificateRequested(
    SSLCertRequestInfo* cert_request_info) {
  status_ = OK;

  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_CERTIFICATE_REQUESTED);
  delegate_->OnCertificateRequested(this, cert_request_info);
}

void URLRequest::NotifySSLCertificateError(int net_error,
                                           const SSLInfo& ssl_info,
                                           bool fatal) {
  status_ = OK;
  OnCallToDelegate(NetLogEventType::URL_REQUEST_DELEGATE_SSL_CERTIFICATE_ERROR);
  delegate_->OnSSLCertificateError(this, net_error, ssl_info, fatal);
}

bool URLRequest::CanSetCookie(
    const net::CanonicalCookie& cookie,
    CookieOptions* options,
    const net::FirstPartySetMetadata& first_party_set_metadata,
    CookieInclusionStatus* inclusion_status) const {
  DCHECK(!(load_flags() & LOAD_DO_NOT_SAVE_COOKIES));
  bool can_set_cookies = g_default_can_use_cookies;
  if (network_delegate()) {
    can_set_cookies = network_delegate()->CanSetCookie(
        *this, cookie, options, first_party_set_metadata, inclusion_status);
  }
  if (!can_set_cookies)
    net_log_.AddEvent(NetLogEventType::COOKIE_SET_BLOCKED_BY_NETWORK_DELEGATE);
  return can_set_cookies;
}

void URLRequest::NotifyReadCompleted(int bytes_read) {
  if (bytes_read > 0)
    set_status(OK);
  // Notify in case the entire URL Request has been finished.
  if (bytes_read <= 0)
    NotifyRequestCompleted();

  // When URLRequestJob notices there was an error in URLRequest's |status_|,
  // it calls this method with |bytes_read| set to -1. Set it to a real error
  // here.
  // TODO(maksims): NotifyReadCompleted take the error code as an argument on
  // failure, rather than -1.
  if (bytes_read == -1) {
    // |status_| should indicate an error.
    DCHECK(failed());
    bytes_read = status_;
  }

  delegate_->OnReadCompleted(this, bytes_read);

  // Nothing below this line as OnReadCompleted may delete |this|.
}

void URLRequest::OnHeadersComplete() {
  // The URLRequest status should still be IO_PENDING, which it was set to
  // before the URLRequestJob was started.  On error or cancellation, this
  // method should not be called.
  DCHECK_EQ(ERR_IO_PENDING, status_);
  set_status(OK);
  // Cache load timing information now, as information will be lost once the
  // socket is closed and the ClientSocketHandle is Reset, which will happen
  // once the body is complete.  The start times should already be populated.
  if (job_.get()) {
    // Keep a copy of the two times the URLRequest sets.
    base::TimeTicks request_start = load_timing_info_.request_start;
    base::Time request_start_time = load_timing_info_.request_start_time;

    // Clear load times.  Shouldn't be neded, but gives the GetLoadTimingInfo a
    // consistent place to start from.
    load_timing_info_ = LoadTimingInfo();
    job_->GetLoadTimingInfo(&load_timing_info_);

    load_timing_info_.request_start = request_start;
    load_timing_info_.request_start_time = request_start_time;

    ConvertRealLoadTimesToBlockingTimes(&load_timing_info_);
  }
}

void URLRequest::NotifyRequestCompleted() {
  // TODO(battre): Get rid of this check, according to willchan it should
  // not be needed.
  if (has_notified_completion_)
    return;

  is_pending_ = false;
  is_redirecting_ = false;
  deferred_redirect_info_.reset();
  has_notified_completion_ = true;
  if (network_delegate())
    network_delegate()->NotifyCompleted(this, job_.get() != nullptr, status_);
}

void URLRequest::OnCallToDelegate(NetLogEventType type) {
  DCHECK(!calling_delegate_);
  DCHECK(blocked_by_.empty());
  calling_delegate_ = true;
  delegate_event_type_ = type;
  net_log_.BeginEvent(type);
}

void URLRequest::OnCallToDelegateComplete(int error) {
  // This should have been cleared before resuming the request.
  DCHECK(blocked_by_.empty());
  if (!calling_delegate_)
    return;
  calling_delegate_ = false;
  net_log_.EndEventWithNetErrorCode(delegate_event_type_, error);
  delegate_event_type_ = NetLogEventType::FAILED;
}

void URLRequest::RecordReferrerGranularityMetrics(
    bool request_is_same_origin) const {
  GURL referrer_url(referrer_);
  bool referrer_more_descriptive_than_its_origin =
      referrer_url.is_valid() && referrer_url.PathForRequestPiece().size() > 1;

  // To avoid renaming the existing enum, we have to use the three-argument
  // histogram macro.
  if (request_is_same_origin) {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.URLRequest.ReferrerPolicyForRequest.SameOrigin", referrer_policy_,
        static_cast<int>(ReferrerPolicy::MAX) + 1);
    UMA_HISTOGRAM_BOOLEAN(
        "Net.URLRequest.ReferrerHasInformativePath.SameOrigin",
        referrer_more_descriptive_than_its_origin);
  } else {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.URLRequest.ReferrerPolicyForRequest.CrossOrigin", referrer_policy_,
        static_cast<int>(ReferrerPolicy::MAX) + 1);
    UMA_HISTOGRAM_BOOLEAN(
        "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin",
        referrer_more_descriptive_than_its_origin);
  }
}

IsolationInfo URLRequest::CreateIsolationInfoFromNetworkAnonymizationKey(
    const NetworkAnonymizationKey& network_anonymization_key) {
  if (!network_anonymization_key.IsFullyPopulated()) {
    return IsolationInfo();
  }

  url::Origin top_frame_origin =
      network_anonymization_key.GetTopFrameSite()->site_as_origin_;

  std::optional<url::Origin> frame_origin;
  if (network_anonymization_key.IsCrossSite()) {
    // If we know that the origin is cross site to the top level site, create an
    // empty origin to use as the frame origin for the isolation info. This
    // should be cross site with the top level origin.
    frame_origin = url::Origin();
  } else {
    // If we don't know that it's cross site to the top level site, use the top
    // frame site to set the frame origin.
    frame_origin = top_frame_origin;
  }

  auto isolation_info = IsolationInfo::Create(
      IsolationInfo::RequestType::kOther, top_frame_origin,
      frame_origin.value(), SiteForCookies(),
      network_anonymization_key.GetNonce());
  // TODO(crbug.com/40852603): DCHECK isolation info is fully populated.
  return isolation_info;
}

ConnectionAttempts URLRequest::GetConnectionAttempts() const {
  if (job_)
    return job_->GetConnectionAttempts();
  return {};
}

void URLRequest::SetRequestHeadersCallback(RequestHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(request_headers_callback_.is_null());
  request_headers_callback_ = std::move(callback);
}

void URLRequest::SetResponseHeadersCallback(ResponseHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(response_headers_callback_.is_null());
  response_headers_callback_ = std::move(callback);
}

void URLRequest::SetEarlyResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  DCHECK(!job_.get());
  DCHECK(early_response_headers_callback_.is_null());
  early_response_headers_callback_ = std::move(callback);
}

void URLRequest::SetIsSharedDictionaryReadAllowedCallback(
    base::RepeatingCallback<bool()> callback) {
  DCHECK(!job_.get());
  DCHECK(is_shared_dictionary_read_allowed_callback_.is_null());
  is_shared_dictionary_read_allowed_callback_ = std::move(callback);
}

void URLRequest::set_socket_tag(const SocketTag& socket_tag) {
  DCHECK(!is_pending_);
  DCHECK(url().SchemeIsHTTPOrHTTPS());
  socket_tag_ = socket_tag;
}
std::optional<net::cookie_util::StorageAccessStatus>
URLRequest::CalculateStorageAccessStatus() const {
  std::optional<net::cookie_util::StorageAccessStatus> storage_access_status =
      network_delegate()->GetStorageAccessStatus(*this);

  auto get_storage_access_value_outcome_if_omitted = [&]()
      -> std::optional<net::cookie_util::SecFetchStorageAccessValueOutcome> {
    if (!network_delegate()->IsStorageAccessHeaderEnabled(
            base::OptionalToPtr(isolation_info().top_frame_origin()), url())) {
      return net::cookie_util::SecFetchStorageAccessValueOutcome::
          kOmittedFeatureDisabled;
    }
    // Avoid attaching the header in cases where credentials are not included in
    // the request.
    if (!allow_credentials_) {
      return net::cookie_util::SecFetchStorageAccessValueOutcome::
          kOmittedRequestOmitsCredentials;
    }
    if (!storage_access_status) {
      return net::cookie_util::SecFetchStorageAccessValueOutcome::
          kOmittedSameSite;
    }
    return std::nullopt;
  };

  auto storage_access_value_outcome =
      get_storage_access_value_outcome_if_omitted();
  if (storage_access_value_outcome) {
    storage_access_status = std::nullopt;
  } else {
    storage_access_value_outcome =
        ConvertSecFetchStorageAccessHeaderValueToOutcome(
            storage_access_status.value());
  }

  base::UmaHistogramEnumeration(
      "API.StorageAccessHeader.SecFetchStorageAccessValueOutcome",
      storage_access_value_outcome.value());

  return storage_access_status;
}

void URLRequest::SetSharedDictionaryGetter(
    SharedDictionaryGetter shared_dictionary_getter) {
  CHECK(!job_.get());
  CHECK(shared_dictionary_getter_.is_null());
  shared_dictionary_getter_ = std::move(shared_dictionary_getter);
}

base::WeakPtr<URLRequest> URLRequest::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

}  // namespace net
