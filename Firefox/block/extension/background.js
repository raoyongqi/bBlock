const allowedUrls = [
  "puiij.com",
  "engrxiv.org",
  "*.silverchair.com",
  "zora.uzh.ch",
  "irbis-nbuv.gov.ua",
  "*.tidymodels.org",
  "*.google.de",
  "ojs.unikom.ac.id",
  "jil.go.jp",
  "pascal-francis.inist.fr",
  "aiem.es",
  "tvst.arvojournals.org",
  "nph.onlinelibrary.wiley.com",
  "webextension.org",
  "lifescied.org",
  "chatgpt.com",
  "www5.informatik.uni-erlangen.de",
  "publishup.uni-potsdam.de",
  "staff.icar.cnr.it",
  "ahajournals.org",
  "*.wandoujia.com",
  "hal.science",
  "dbpia.co.kr",
  "repository.universitasbumigora.ac.id",
  "karger.com",
  "scielo.br",
  "*.springer.com",
  "ijiset.com",
  "aitskadapa.ac.in",
  "gitlab.com",
  "proceedings.stis.ac.id",
  "rotman-baycrest.on.ca",
  "ijprems.com",
  "article.stmacademicwriting.com",
  "staff.science.uu.nl",
  "michaelfullan.ca",
  "soil.copernicus.org",
  "fardapaper.ir",
  "bjo.bmj.com",
  "ws",
  "learning1to1.net",
  "jstor.org",
  "kb.osu.edu",
  "diglib.eg.org",
  "courses.cs.duke.edu",
  "iris.unitn.it",
  "aanda.org",
  "pubs.asha.org",
  "aab.copernicus.org",
  "researchportal.bath.ac.uk",
  "digibug.ugr.es",
  "jov.arvojournals.org",
  "agupubs.onlinelibrary.wiley.com",
  "data.ornldaac.earthdata.nasa.gov",
  "learntechlib.org",
  "dergipark.org.tr",
  "bura.brunel.ac.uk",
  "apktool.org",
  "*.els-cdn.com",
  "jlc.jst.go.jp",
  "emro.who.int",
  "mednexus.org",
  "sidalc.net",
  "pypi.org",
  "repository.library.carleton.ca",
  "proceedings.esri.com",
  "eprints.utm.my",
  "archium.ateneo.edu",
  "apsjournals.apsnet.org",
  "koreascience.kr",
  "ion.org",
  "journals.openedition.org",
  "go.gale.com",
  "research.rug.nl",
  "*.music.126.net",
  "agsjournals.onlinelibrary.wiley.com",
  "ijml.org",
  "easy.dans.knaw.nl",
  "cathi.uacj.mx",
  "synapse.koreamed.org",
  "zwang4.github.io",
  "climatechange.ai",
  "*.apta.gov.cn",
  "flickerfree.org",
  "personales.upv.es",
  "rgs-ibg.onlinelibrary.wiley.com",
  "publichealth.jmir.org",
  "*.ssrn.com",
  "lalavision.com",
  "*.mdpi-res.com",
  "humanfactors.jmir.org",
  "apps.dtic.mil",
  "repository.library.noaa.gov",
  "xlescience.org",
  "jmirs.org",
  "*.microsoft.com",
  "cs.columbia.edu",
  "journal.cartography.or.kr",
  "spatial.usc.edu",
  "*.github.com",
  "dr.ntu.edu.sg",
  "syxb-cps.com.cn",
  "scielo.org.mx",
  "journal.universitasbumigora.ac.id",
  "eric.ed.gov",
  "lyellcollection.org",
  "ntrs.nasa.gov",
  "formative.jmir.org",
  "isip.piconepress.com",
  "jecr.org",
  "jurnal.researchideas.org",
  "scholarworks.smith.edu",
  "jbds.isdsa.org",
  "ecology.ghislainv.fr",
  "uwe-repository.worktribe.com",
  "vipsi.org",
  "digitalscholarship.unlv.edu",
  "enviromicro-journals.onlinelibrary.wiley.com",
  "reprints.gravitywaves.com",
  "hpi.uni-potsdam.de",
  "peerj.com",
  "aka.ms",
  "*.hubspot.com",
  "jstatsoft.org",
  "*.dkut.ac.ke",
  "researchcommons.waikato.ac.nz",
  "*.nasa.gov",
  "arcgis.com",
  "icaci.org",
  "docs.lib.purdue.edu",
  "ajph.aphapublications.org",
  "springer.com",
  "*.cookielaw.org",
  "jcsdcb.com",
  "joces.nudt.edu.cn",
  "rodconnolly.com",
  "oneecosystem.pensoft.net",
  "jmir.org",
  "bright-journal.org",
  "epubs.siam.org",
  "*.alicdn.com",
  "serpapi.com",
  "e-jwj.org",
  "journals2.ums.ac.id",
  "ambridge.org",
  "ntut.elsevierpure.com",
  "asistdl.onlinelibrary.wiley.com",
  "cell.com",
  "scielosp.org",
  "journals.asm.org",
  "indico.ifj.edu.pl",
  "personality-project.org",
  "sf-conference.eu",
  "spandidos-publications.com",
  "adsabs.harvard.edu",
  "stats.ox.ac.uk",
  "sisis.rz.htw-berlin.de",
  "scielo.org.za",
  "essd.copernicus.org",
  "jurnal.polsri.ac.id",
  "seas.upenn.edu",
  "rose.geog.mcgill.ca",
  "acm.org",
  "*.clemson.edu",
  "*.rust-lang.org",
  "projectpythia.org",
  "files.eric.ed.gov",
  "*.live.com",
  "researchonline.gcu.ac.uk",
  "lexjansen.com",
  "elea.unisa.it",
  "eprint.iacr.org",
  "*.lzu.edu.cn",
  "cambridge.org",
  "jgit.kntu.ac.ir",
  "*.qt.io",
  "ejournal.seaninstitute.or.id",
  "*.xarray.dev",
  "*.strongvpn.com",
  "bsapubs.onlinelibrary.wiley.com",
  "epa.niif.hu",
  "physicamedica.com",
  "cyxb.magtech.com.cn",
  "repository.unika.ac.id",
  "rbciamb.com.br",
  "airitilibrary.com",
  "researchplusjournal.com",
  "biomedicaljour.com",
  "file.fouladi.ir",
  "liebertpub.com",
  "repository.iep.bg.ac.rs",
  "journal.neolectura.com",
  "geopandas.org",
  "politesi.polimi.it",
  "dora.lib4ri.ch",
  "agile-gi.eu",
  "hcjournal.org",
  "ijme.mui.ac.ir",
  "repository.kisti.re.kr",
  "igi-global.com",
  "service.seamlessaccess.org",
  "bookdown.org",
  "cs.tufts.edu",
  "designsociety.org",
  "datascienceassn.org",
  "compass.onlinelibrary.wiley.com",
  "pdfs.semanticscholar.org",
  "*.gstatic.com",
  "scholar.its.ac.id",
  "gmd.copernicus.org",
  "ias.ac.in",
  "philsci-archive.pitt.edu",
  "*.sagepub.com",
  "prism.ucalgary.ca",
  "gtg.webhost.uoradea.ro",
  "jurnal.polinema.ac.id",
  "dash.harvard.edu",
  "jurnal.likmi.ac.id",
  "journals.sfu.ca",
  "bio-conferences.org",
  "staff.fnwi.uva.nl",
  "europepmc.org",
  "seer.ufu.br",
  "ieeexplore.ieee.org",
  "*.biomedcentral.com",
  "repository.gatech.edu",
  "yuque.com",
  "aapm.onlinelibrary.wiley.com",
  "img-prod-cms-rt-microsoft-com.akamaized.net",
  "erepository.uonbi.ac.ke",
  "par.nsf.gov",
  "redux.js.org",
  "vite.dev",
  "research.bangor.ac.uk",
  "vadl2017.github.io",
  "*.weixin.qq.com",
  "mail.qq.com",
  "scholarworks.gsu.edu",
  "aaltodoc.aalto.fi",
  "dataorigami.net",
  "djournals.com",
  "degruyter.com",
  "elifesciences.org",
  "ijmh.org",
  "sjdz.jlu.edu.cn",
  "ijcoa.com",
  "aimspress.com",
  "irojournals.com",
  "oaepublish.com",
  "ijtech.eng.ui.ac.id",
  "jurnal.yoctobrain.org",
  "guilfordjournals.com",
  "catsr.vse.gmu.edu",
  "eartharxiv.org",
  "aiej.org",
  "bibliotekanauki.pl",
  "thilowellmann.de",
  "library.oapen.org",
  "imgcache.qq.com",
  "nwr.gov.cn",
  "41.59.85.213",
  "infeb.org",
  "api.taylorfrancis.com",
  "*.kaggle.io",
  "journal.admi.or.id",
  "jove.com",
  "elib.psu.by",
  "papers.ssrn.com",
  "scijournals.onlinelibrary.wiley.com",
  "apiacoa.org",
  "edepot.wur.nl",
  "acp.copernicus.org",
  "iris.uniroma1.it",
  "scholarworks.calstate.edu",
  "dspace.library.uvic.ca",
  "airccj.org",
  "ir.lib.uwo.ca",
  "scirp.org",
  "fjs.fudutsinma.edu.ng",
  "jbc.org",
  "geodetski-vestnik.com",
  "nuxt.com",
  "gfzpublic.gfz-potsdam.de",
  "bodden.de",
  "learningsys.org",
  "accounts.google.com.np",
  "forestchemicalsreview.com",
  "python.org",
  "repository.isls.org",
  "journals.plos.org",
  "*.ansfoundation.org",
  "pgmpy.org",
  "*.office.net",
  "dev.icaci.org",
  "ieee-ims.org",
  "geoviews.org",
  "*.aliapp.org",
  "plausible.io",
  "repository.uin-malang.ac.id",
  "agritrop.cirad.fr",
  "researchspace.auckland.ac.nz",
  "cit.ctu.edu.vn",
  "webofknowledge.com",
  "eltikom.poliban.ac.id",
  "newjaigs.com",
  "mlpp.pressbooks.pub",
  "iaap-journals.onlinelibrary.wiley.com",
  "journal.iba-suk.edu.pk",
  "*.ucdl.pp.uc.cn",
  "educationaldatamining.org",
  "pubs.aip.org",
  "jsod-cieo.net",
  "open.bu.edu",
  "webthesis.biblio.polito.it",
  "openresearchsoftware.metajnl.com",
  "ebooks.iospress.nl",
  "softcomputing.net",
  "natuurtijdschriften.nl",
  "scholarbank.nus.edu.sg",
  "idus.us.es",
  "socialwork.wayne.edu",
  "papers.phmsociety.org",
  "jamanetwork.com",
  "pytorch.org",
  "cmake.org",
  "shizuku.rikka.app",
  "mecs-press.org",
  "citeseerx.ist.psu.edu",
  "magisz.org",
  "matec-conferences.org",
  "*.googlesyndication.com",
  "zslpublications.onlinelibrary.wiley.com",
  "mae.ucf.edu",
  "ascopubs.org",
  "webofscience.com",
  "inria.hal.science",
  "captcha.gtimg.com",
  "research.tue.nl",
  "ecoagri.ac.cn",
  "ij-aquaticbiology.com",
  "joss.theoj.org",
  "*.esri.com",
  "erj.ersjournals.com",
  "repositorio.unesp.br",
  "arlis.org",
  "cv-foundation.org",
  "gee-community-catalog.org",
  "*.visualwebsiteoptimizer.com",
  "academicjournals.org",
  "*.kaggleusercontent.com",
  "croris.hr",
  "geoanalytics.net",
  "assets-eu.researchsquare.com",
  "assets.pubpub.org",
  "ehp.niehs.nih.gov",
  "ijcsrr.org",
  "doria.fi",
  "f1000research.com",
  "researchgate.net",
  "lmb.informatik.uni-freiburg.de",
  "cal-tek.eu",
  "dspace.rsu.lv",
  "*.mail.qq.com",
  "browser-intake-datadoghq.com",
  "ndl.ethernet.edu.et",
  "repository.lboro.ac.uk",
  "udrc.eng.ed.ac.uk",
  "cp.copernicus.org",
  "ejmste.com",
  "logic.pdmi.ras.ru",
  "repositorio.uteq.edu.ec",
  "indianecologicalsociety.com",
  "cdigital.uv.mx",
  "rubytec.eu",
  "fs.usda.gov",
  "edoc.ub.uni-muenchen.de",
  "usenix.org",
  "journals.aps.org",
  "repositories.lib.utexas.edu",
  "admis.tongji.edu.cn",
  "alipay.com",
  "geospatialhealth.net",
  "portlandpress.com",
  "vtechworks.lib.vt.edu",
  "deeplearning.ir",
  "f-droid.org",
  "numfocus.org",
  "dspace.aztidata.es",
  "wires.onlinelibrary.wiley.com",
  "ee.cuhk.edu.hk",
  "acsess.onlinelibrary.wiley.com",
  "journal.lenterailmu.com",
  "ch.whu.edu.cn",
  "structuraltopicmodel.com",
  "keep.lib.asu.edu",
  "openaccess.city.ac.uk",
  "*.jinshujufiles.com",
  "people.cs.uct.ac.za",
  "*.alibabachengdun.com",
  "jne.ut.ac.ir",
  "ejournal.unma.ac.id",
  "jair.org",
  "peer.asee.org",
  "rosap.ntl.bts.gov",
  "pofflab.colostate.edu",
  "researchcghe.org",
  "*.psu.edu",
  "repository.law.indiana.edu",
  "connormwood.com",
  "*.adobedtm.com",
  "repository.arizona.edu",
  "s.gravatar.com",
  "iforest.sisef.org",
  "theses.hal.science",
  "*.googleapis.com",
  "elibrary.ru",
  "d-nb.info",
  "*.typekit.net",
  "*.conicet.gov.ar",
  "journal.dcs.or.kr",
  "*.wiley.com",
  "tc.copernicus.org",
  "aclanthology.org",
  "eprints.fri.uni-lj.si",
  "esploro.libs.uga.edu",
  "docs.huihoo.com",
  "digital.library.txstate.edu",
  "adgeo.copernicus.org",
  "geomatik-hamburg.de",
  "cs.cmu.edu",
  "tethys.pnl.gov",
  "iibajournal.org",
  "arodes.hes-so.ch",
  "academic.oup.com",
  "holoviews.org",
  "research.aalto.fi",
  "sciendo.com",
  "josis.org",
  "tensorflow-dot-devsite-v2-prod-3p.appspot.com",
  "search.ieice.org",
  "*.oracle.com",
  "*.berkeley.edu",
  "worldscientific.com",
  "digital.csic.es",
  "journal.lu.lv",
  "mdag.com",
  "geography.ryerson.ca",
  "*.qutebrowser.org",
  "uknowledge.uky.edu",
  "jstage.jst.go.jp",
  "repository.lsu.edu",
  "*.siam.org",
  "worldclim.org",
  "journals.healio.com",
  "bsppjournals.onlinelibrary.wiley.com",
  "eas-journal.org",
  "researchnow.flinders.edu.au",
  "ceur-ws.org",
  "gitlab.jsc.fz-juelich.de",
  "alipayobjects.com",
  "unitec.ac.nz",
  "matplotlib.org",
  "*.sun.ac.za",
  "qzapp.qlogo.cn",
  "openproceedings.org",
  "inderscienceonline.com",
  "react-redux.js.org",
  "digitalcommons.buffalostate.edu",
  "dipterajournal.com",
  "*.sciencedirect.com",
  "*.gyan.dev",
  "figshare.com",
  "bg.copernicus.org",
  "digital.lib.washington.edu",
  "is.ocha.ac.jp",
  "jmis.org",
  "*.hsforms.net",
  "efmaefm.org",
  "opg.optica.org",
  "res.wx.qq.com",
  "pubs.rsc.org",
  "ffmpeg.org",
  "ojs.sgsci.org",
  "ijsdcs.com",
  "rustup.rs",
  "*.graph.qq.com",
  "techrxiv.org",
  "oup.silverchair-cdn.com",
  "cmap.polytechnique.fr",
  "dlsu.edu.ph",
  "trisala.salatiga.go.id",
  "kosovaanthropologica.com",
  "qmro.qmul.ac.uk",
  "ijlaitse.com",
  "fonts.loli.net",
  "pydub.com",
  "lavaan.org",
  "journals.library.ualberta.ca",
  "pmc.ncbi.nlm.nih.gov",
  "cse512-15s.github.io",
  "ntnuopen.ntnu.no",
  "statmodeling.stat.columbia.edu",
  "sbleis.ch",
  "research.google.com",
  "sk.sagepub.com",
  "ssoar.info",
  "ajce.aut.ac.ir",
  "library-archives.canada.ca",
  "fmv.nau.edu.ua",
  "hm.baidu.com",
  "cair.org",
  "pubsonline.informs.org",
  "www2.jpgu.org",
  "codelibrary.info",
  "scholarpedia.org",
  "digital.wpi.edu",
  "psysci.org",
  "ecoevorxiv.org",
  "tobaccocontrol.bmj.com",
  "unpkg.com",
  "econstor.eu",
  "digitalcommons.calpoly.edu",
  "search.proquest.com",
  "wandoujia.com",
  "dl.gi.de",
  "nuriaoliver.com",
  "ijcai.org",
  "cartographicperspectives.org",
  "embopress.org",
  "spiedigitallibrary.org",
  "thuvienso.hoasen.edu.vn",
  "intereuroconf.com",
  "bib.irb.hr",
  "ifej.sanru.ac.ir",
  "*.25pp.com",
  "sciltp.com",
  "*.cloudflare.com",
  "tobias-lib.ub.uni-tuebingen.de",
  "report.qqweb.qq.com",
  "platform-api.sharethis.com",
  "electronjs.org",
  "changfengbox.top",
  "*.hanspub.org",
  "tidsskrift.dk",
  "tensorflow.org",
  "scitepress.org",
  "knowledgecenter.ubt-uni.net",
  "jait.us",
  "featureassets.org",
  "pressto.amu.edu.pl",
  "*.nih.gov",
  "selenium.dev",
  "kyushu-u.elsevierpure.com",
  "meridian.allenpress.com",
  "*.journal-grail.science",
  "jutif.if.unsoed.ac.id",
  "atlantis-press.com",
  "nanobe.org",
  "sciopen.com",
  "repository.mdx.ac.uk",
  "digitalcommons.library.tmc.edu",
  "developer.android.com",
  "shubhanshu.com",
  "*.aliyun.com",
  "bigr.io",
  "studenttheses.uu.nl",
  "ingentaconnect.com",
  "library.wur.nl",
  "h2o-release.s3.amazonaws.com",
  "docs.geetest.com",
  "iovs.arvojournals.org",
  "digitalcommons.memphis.edu",
  "ejournal.undip.ac.id",
  "scholar.lib.ntnu.edu.tw",
  "jmasm.com",
  "frida.re",
  "ideas.repec.org",
  "analytics.ng",
  "zenodo.org",
  "powertechjournal.com",
  "nsojournals.onlinelibrary.wiley.com",
  "ejournal.stiepena.ac.id",
  "science.org",
  "cgspace.cgiar.org",
  "docs.neu.edu.tr",
  "*.doi.org",
  "jinav.org",
  "helda.helsinki.fi",
  "awesome-poetry.top",
  "research-collection.ethz.ch",
  "scholarsarchive.byu.edu",
  "idpublications.org",
  "smujo.id",
  "researchportal.murdoch.edu.au",
  "ietresearch.onlinelibrary.wiley.com",
  "git-scm.com",
  "epstem.net",
  "dsr.inpe.br",
  "k0d.cc",
  "eprints.lse.ac.uk",
  "sciencedirect.com",
  "doi.org",
  "pure.mpg.de",
  "aacrjournals.org",
  "eprints.umsida.ac.id",
  "brill.com",
  "scpe.org",
  "people.csail.mit.edu",
  "gispoint.de",
  "*.allenpress.com",
  "strongvpn.com",
  "hlevkin.com",
  "digitalcommons.usu.edu",
  "esann.org",
  "littlefreedigitallibrary.com",
  "*.kaggle.com",
  "ams.confex.com",
  "elibrary.asabe.org",
  "*.riskified.com",
  "xarray.dev",
  "*.audacityteam.org",
  "nowpublishers.com",
  "isprs-annals.copernicus.org",
  "pyro.ai",
  "geochina.cgs.gov.cn",
  "preprints.org",
  "datajobs.com",
  "medicinskiglasnik.ba",
  "yadda.icm.edu.pl",
  "icai.ektf.hu",
  "journals.physiology.org",
  "aloki.hu",
  "esj-journals.onlinelibrary.wiley.com",
  "scholarworks.umt.edu",
  "jidt.org",
  "passmark.com",
  "iccgis2018.cartography-gis.com",
  "epub.ub.uni-greifswald.de",
  "adac.ee",
  "ijecom.org",
  "playwright.dev",
  "cris.bgu.ac.il",
  "sto.nato.int",
  "wechat-article-exporter.deno.dev",
  "reabic.net",
  "drops.dagstuhl.de",
  "sid.ir",
  "boa.unimib.it",
  "cummings-lab.org",
  "*.office.com",
  "humanit.hb.se",
  "tore.tuhh.de",
  "dovepress.com",
  "genome.cshlp.org",
  "vis.cs.ucdavis.edu",
  "docs-neteasecloudmusicapi.vercel.app",
  "theoj.org",
  "proceedings.neurips.cc",
  "agile-giss.copernicus.org",
  "nrl.northumbria.ac.uk",
  "trid.trb.org",
  "hal.univ-grenoble-alpes.fr",
  "*.osgeo.org",
  "flowchart.js.org",
  "*.s3.amazonaws.com",
  "gcdz.org",
  "journals.ametsoc.org",
  "aeaweb.org",
  "diva-portal.org",
  "*.ptlogin2.qq.com",
  "predictive-workshop.github.io",
  "publish.mersin.edu.tr",
  "sci2s.ugr.es",
  "repository.kulib.kyoto-u.ac.jp",
  "alz-journals.onlinelibrary.wiley.com",
  "ashpublications.org",
  "link.springer.com",
  "nmbu.brage.unit.no",
  "www1.cs.columbia.edu",
  "cje.ustb.edu.cn",
  "pubs.geoscienceworld.org",
  "shs.hal.science",
  "aas.net.cn",
  "setac.onlinelibrary.wiley.com",
  "icaarconcrete.org",
  "geolib.geo.auth.gr",
  "marginaleffects.com",
  "*.mlr.press",
  "scholar.archive.org",
  "eprints.soton.ac.uk",
  "eprints.qut.edu.au",
  "annualreviews.org",
  "ssl.ptlogin2.graph.qq.com",
  "nodejs.org",
  "*.cloudfront.net",
  "*.springernature.com",
  "hess.copernicus.org",
  "ijlter.org",
  "ira.lib.polyu.edu.hk",
  "ift.onlinelibrary.wiley.com",
  "mdpi.com",
  "osti.gov",
  "*.alipayobjects.com",
  "analises-ecologicas.com",
  "scholarworks.alaska.edu",
  "*.nature.com",
  "tunasbangsa.ac.id",
  "bit.ly",
  "eprints.gla.ac.uk",
  "eneuro.org",
  "hal-ciheam.iamm.fr",
  "*.elsevier.com",
  "ojs.lib.unideb.hu",
  "nora.nerc.ac.uk",
  "essay.utwente.nl",
  "*.posit.co",
  "ikg.uni-hannover.de",
  "stat.washington.edu",
  "*.oaistatic.com",
  "books.google.com",
  "sv-journal.org",
  "*.r-lib.org",
  "pubs.usgs.gov",
  "journals.flvc.org",
  " fourier.taobao.com",
  "eprints.cihanuniversity.edu.iq",
  "liverpooluniversitypress.co.uk",
  "users.eecs.northwestern.edu",
  "*.cdn-go.cn",
  "*.holoviz.org",
  "openresearch.surrey.ac.uk",
  "*.researchcommons.org",
  "ageconsearch.umn.edu",
  "journalinstal.cattleyadf.org",
  "badge.dimensions.ai",
  "lit2talks.com",
  "kaggle.com",
  "*.biologists.com",
  "dlib.hust.edu.vn",
  "tristan.cordier.free.fr",
  "*.googletagmanager.com",
  "incaindia.org",
  "*.arxiv.org",
  "microsoft.com",
  "kar.kent.ac.uk",
  "conference.sdo.esoc.esa.int",
  "anatomypubs.onlinelibrary.wiley.com",
  "nyaspubs.onlinelibrary.wiley.com",
  "*.uclouvain.be",
  "ascpt.onlinelibrary.wiley.com",
  "www.52pojie.cn",
  "*.torontomu.ca",
  "direct.mit.edu",
  "ora.ox.ac.uk",
  "cogvis.icaci.org",
  "ajol.info",
  "*.r-project.org",
  "dea.lib.unideb.hu",
  "*.jinshujucdn.com",
  "*.qqmail.com",
  "faculty.educ.ubc.ca",
  "witpress.com",
  "httpbin.org",
  "er.chdtu.edu.ua",
  "eurasianpublications.com",
  "onlinelibrary.wiley.com",
  "gdal.org",
  "cdr.lib.unc.edu",
  "medrxiv.org",
  "nber.org",
  "*.iop.org",
  "cirlmemphis.com",
  "vizml.media.mit.edu",
  "*.kde.org",
  "stars.library.ucf.edu",
  "journal.r-project.org",
  "is.muni.cz",
  "google.com",
  "studiostaticassetsprod.azureedge.net",
  "oa.upm.es",
  "waseda.elsevierpure.com",
  "ijmge.ut.ac.ir",
  "academicradiology.org",
  "vestnikskfu.elpub.ru",
  "*.googlesource.com",
  "repository.ubn.ru.nl",
  "cdnsciencepub.com",
  "archive.ismrm.org",
  "daac.ornl.gov",
  "ojs.cvut.cz",
  "bme.ufl.edu",
  "ceeol.com",
  "research.utwente.nl",
  "vbn.aau.dk",
  "drive.google.com",
  "*.simpleanalyticscdn.com",
  "*.sonaliyadav.workers.dev",
  "iipseries.org",
  "*.jsdelivr.net",
  "revistafesahancccal.org",
  "flore.unifi.it",
  "ink.library.smu.edu.sg",
  "journal.rescollacomm.com",
  "rmets.onlinelibrary.wiley.com",
  "isas.org.in",
  "openaging.com",
  "repository.umy.ac.id",
  "cloudflare.com",
  "bera-journals.onlinelibrary.wiley.com",
  "fonts.gstatic.com",
  "gbpihed.gov.in",
  "advances.in",
  "chemrxiv.org",
  "kops.uni-konstanz.de",
  "researchportal.port.ac.uk",
  "publica.fraunhofer.de",
  "philstat.org",
  "royalsocietypublishing.org",
  "imis.uni-luebeck.de",
  "telkomnika.uad.ac.id",
  "eprints.whiterose.ac.uk",
  "swsc-journal.org",
  "igb.uci.edu",
  "api.altmetric.com",
  "icevirtuallibrary.com",
  "ere.ac.cn",
  "tandfonline.com",
  "currentprotocols.onlinelibrary.wiley.com",
  "iase-web.org",
  "*.chatgpt.com",
  "ellenhamaker.github.io",
  "lib.baomitu.com",
  "btstu.researchcommons.org",
  "*.tensorflow.org",
  "journals.co.za",
  "nsg.repo.nii.ac.jp",
  "corinne-vacher.com",
  "int-res.com",
  "arxiv.org",
  "arc.aiaa.org",
  "utpjournals.press",
  "amt.copernicus.org",
  "taylorfrancis.com",
  "mocom.xmu.edu.cn",
  "serena.unina.it",
  "krex.k-state.edu",
  "iaee.org",
  "openai.com",
  "drpress.org",
  "digital-library.theiet.org",
  "durham-repository.worktribe.com",
  "lib.unib.ac.id",
  "resjournals.onlinelibrary.wiley.com",
  "*.gradle.org",
  "ajnr.org",
  "deno.com",
  "tianditu.gov.cn",
  "epub.uni-regensburg.de",
  "*.alipay.com",
  "inis.iaea.org",
  "scienceopen.com",
  "cartogis.org",
  "naec.org.uk",
  "angeo.copernicus.org",
  "besjournals.onlinelibrary.wiley.com",
  "proceedings.mlr.press",
  "jcrinn.com",
  "journal.psych.ac.cn",
  "cse.unsw.edu.au",
  "journal.irpi.or.id",
  "dline.info",
  "iaees.org",
  "etd.ohiolink.edu",
  "journals.vilniustech.lt",
  "disi.unitn.it",
  "joig.net",
  "mtkxjs.com.cn",
  "ojs.library.queensu.ca",
  "sentic.net",
  "elib.dlr.de",
  "gram.web.uah.es",
  "iocscience.org",
  "ir.library.oregonstate.edu",
  "esajournals.onlinelibrary.wiley.com",
  "jstnar.iut.ac.ir",
  "scihorizon.com",
  "seamlessaccess.org",
  "terradigitalis.igg.unam.mx",
  "ascelibrary.org",
  "ager.yandypress.com",
  "cse.fau.edu",
  "ri.conicet.gov.ar",
  "*.wpscdn.com",
  "etamaths.com",
  "files.sisclima.it",
  "projectstorm.cloud",
  "idjs.ca",
  "digitalcommons.library.umaine.edu",
  "orbi.uliege.be",
  "infoscience.epfl.ch",
  "content.iospress.com",
  "hdsr.mitpress.mit.edu",
  "caffeineviking.net",
  "swdzgcdz.com",
  "code.earthengine.google.com",
  "iasj.net",
  "tqmp.org",
  "repositorio.ufsc.br",
  "*.gongkaoshequ.com",
  "repository.kaust.edu.sa",
  "journals.aom.org",
  "bmj.com",
  "air.ashesi.edu.gh",
  "nopr.niscpr.res.in",
  "scipost.org",
  "covert.io",
  "cdn.techscience.cn",
  "cse.iitkgp.ac.in",
  "ddkang.github.io",
  "mce.biophys.msu.ru",
  "journal.genintelektual.id",
  "discovery.ucl.ac.uk",
  "policycommons.net",
  "scis.scichina.com",
  "idl.iscram.org",
  "hrcak.srce.hr",
  "jmes.humg.edu.vn",
  "kiss.kstudy.com",
  "sscdigitalstorytelling.pbworks.com",
  "*.neea.edu.cn",
  "researchsquare.com",
  "journals.riverpublishers.com",
  "live.com",
  "mercurial-scm.org",
  "tallinzen.net",
  "prodregistryv2.org",
  "tspace.library.utoronto.ca",
  "lup.lub.lu.se",
  "cir.nii.ac.jp",
  "dada.cs.washington.edu",
  "semarakilmu.com.my",
  "ijciras.com",
  "doc.ic.ac.uk",
  "distill.pub",
  "jsj.top",
  "raw.githubusercontent.com",
  "open.library.ubc.ca",
  "iris.unipa.it",
  "repositori.upf.edu",
  "duo.uio.no",
  "bdtd.ibict.br",
  "knowledgewords.com",
  "philarchive.org",
  "biorxiv.org",
  "periodicos.ufpe.br",
  "nature.com",
  "caislab.kaist.ac.kr",
  "www.wjx.cn",
  "mhealth.jmir.org",
  "centaur.reading.ac.uk",
  "*.aligames.com",
  "reproducible-builds.org",
  ",*.cnzz.com",
  "web2py.iiit.ac.in",
  "ofai.at",
  "ant.design",
  "joiv.org",
  "pubs.acs.org",
  "escholarship.mcgill.ca",
  "biomisa.org",
  "ejournal.svgacademy.org",
  "academic-pub.org",
  "editor.md.ipandao.com",
  "vinar.vin.bg.ac.rs",
  "dione.lib.unipi.gr",
  "midwifery.iocspublisher.org",
  "mediatum.ub.tum.de",
  "brgm.hal.science",
  "igj-iraq.org",
  "figshare.utas.edu.au",
  "statmath.wu.ac.at",
  "w3.mi.parisdescartes.fr",
  "rss.onlinelibrary.wiley.com",
  "gisak.vsb.cz",
  "amostech.com",
  "scholarworks.iupui.edu",
  "*.npmjs.com",
  "ajemb.us",
  "kharazmi-statistics.ir",
  "viz.icaci.org",
  "106.54.215.74",
  "projecteuclid.org",
  "cityterritoryarchitecture.springeropen.com",
  "publish.csiro.au",
  "wps.com",
  "accounts.google.de",
  "*.informs.org",
  "*.aliyuncs.com",
  "ui.adsabs.harvard.edu",
  "enos.itcollege.ee",
  "machineintelligenceresearchs.com",
  "zz.bdstatic.com",
  "ideapublishers.org",
  "journal.code4lib.org",
  "cbml.science",
  "journals.humankinetics.com",
  "*.usgs.gov",
  "psycnet.apa.org",
  "stacks.cdc.gov",
  "graph.qq.com",
  "journal-dogorangsang.in",
  "frontiersin.org",
  "wfs.swst.org",
  "fellenius.net",
  "*.oaiusercontent.com",
  "philpapers.org",
  "wildlife.onlinelibrary.wiley.com",
  "isca-archive.org",
  "dusk.geo.orst.edu",
  "jau.vgtu.lt",
  "ideals.illinois.edu",
  "webapps.fhsu.edu",
  "jos.unsoed.ac.id",
  "repositorio.ipcb.pt",
  "*.captcha.qq.com",
  "ocgy.ubc.ca",
  "office.sjas-journal.org",
  "bsssjournals.onlinelibrary.wiley.com",
  "keevin60907.github.io",
  "cs.toronto.edu",
  "torrossa.com",
  "scholar.smu.edu",
  "icir.org",
  "*.mlr-org.com",
  "library.seg.org",
  "journals.uchicago.edu",
  "uge-share.science.upjs.sk",
  "scrapy.org",
  "conbio.onlinelibrary.wiley.com",
  "aegis.qq.com",
  "*.openai.com",
  "earthdoc.org",
  "research-portal.uu.nl",
  "era.library.ualberta.ca",
  "core.ac.uk",
  "10.10.0.166",
  "febs.onlinelibrary.wiley.com",
  "fit.vutbr.cz",
  "pages.cs.wisc.edu",
  "*.9game.cn",
  "orbilu.uni.lu",
  "kims-imio.kz",
  "academia.edu",
  "music.163.com",
  "ieeeprojects.eminents.in",
  "emerald.com",
  "giirj.com",
  "pure.iiasa.ac.at",
  "isprs-archives.copernicus.org",
  "detectportal.firefox.com",
  "jae-tech.com",
  "ruor.uottawa.ca",
  "*.52pojie.cn",
  "wiredspace.wits.ac.za",
  "*.readthedocs.org",
  "journalskuwait.org",
  "iopscience.iop.org",
  "*.msftconnecttest.com",
  "cabidigitallibrary.org",
  "*.github.io",
  "xyflow.com",
  "bam.nr-data.net",
  "iaeng.org",
  "heinonline.org",
  "bpspsychub.onlinelibrary.wiley.com",
  "jeb.co.in",
  "felipebravom.com",
  "*.theoj.org",
  "popcenter.asu.edu",
  "js.trendmd.com",
  "*.microsoftonline.com",
  "openaccess.thecvf.com",
  "*.sinaimg.cn",
  "scraperapi.com",
  "econtent.hogrefe.com",
  "bmjopen.bmj.com",
  "hackveda.in",
  "informatica.si",
  "apsnet.org",
  "scb.se",
  "catalog.ggau.by",
  "kalaharijournals.com",
  "ecosimpro.com",
  "s3.ca-central-1.amazonaws.com",
  "wins.or.kr",
  "journals.sagepub.com",
  "iwaponline.com",
  "mavmatrix.uta.edu",
  "*.githubusercontent.com",
  "analyticalsciencejournals.onlinelibrary.wiley.com",
  "*.deno.dev",
  "sci-hub.gg",
  "rupress.org",
  "meetingorganizer.copernicus.org",
  "github.com",
  "openreview.net",
  "www2.papelesdelpsicologo.es",
  "ir.cwi.nl",
  "*.nvidia.com",
  "*.readthedocs.io",
  "wikiworkshop.org",
  "ggepi.lukewjohnston.com",
  "thelancet.com",
  "egusphere.copernicus.org",
  "experts.umn.edu",
  "keras.io",
  "e3s-conferences.org",
  "aiche.onlinelibrary.wiley.com",
  "cyberleninka.ru",
  "run.unl.pt",
  "burjcdigital.urjc.es",
  "acikerisim.uludag.edu.tr",
  "aslopubs.onlinelibrary.wiley.com",
  "muse.jhu.edu",
  "*.aegis.qq.com",
  "int-arch-photogramm-remote-sens-spatial-inf-sci.net",
  "reactnative.cn",
  "indianjournals.com",
  "g.3gl.net",
  "*.mmstat.com",
  "ise.ncsu.edu",
  "ece.neu.edu",
  "cs.ccsu.edu",
  "pages.charlotte.edu",
  "ijcst.journals.yorku.ca",
  "dialnet.unirioja.es",
  "pqm.unibe.ch",
  "ueaeprints.uea.ac.uk",
  "bakerlab.org",
  "localhost",
  "msftconnecttest.com",
  "alyssax.com",
  "irjaes.com",
  "nhess.copernicus.org",
  "tauri.app",
  "web.pdx.edu",
  "osf.io",
  "sendimage.whu.edu.cn",
  "gato-docs.its.txstate.edu",
  "redux-toolkit.js.org",
  "*.acm.org",
  "srcd.onlinelibrary.wiley.com",
  "anapub.co.ke",
  "beei.org",
  "calhoun.nps.edu",
  "authorea.com",
  "perpustakaan.atmaluhur.ac.id",
  "*.163.com",
  "mental.jmir.org",
  "xb.chinasmp.com",
  "escholarship.org",
  "alochana.org",
  "pptr.dev",
  "ijadis.org",
  "dl.acm.org",
  "aseestant.ceon.rs",
  "*.netzel.pl",
  "frankxue.com",
  "*.codabench.org",
  "*.scraperapi.com",
  "*.privado.ai",
  "sp0.baidu.com",
  "mc-stan.org",
  "www-ai.ijs.si",
  "cerf.radiologie.fr",
  "ncbi.nlm.nih.gov",
  "cje.net.cn",
  "cad-journal.net",
  "scitools.org.uk",
  "*.unl.edu",
  "ecmlpkdd2017.ijs.si",
  "journals.um.si",
  "physics.brown.edu",
  "acikerisim.fsm.edu.tr",
  "researchbank.ac.nz",
  "*.deno.com",
  "riunet.upv.es",
  "onepetro.org",
  "fondazionemcr.it",
  "computer.org",
  "publikationen.ub.uni-frankfurt.de",
  "*.scienceconnect.io",
  "ica-proc.copernicus.org",
  "b-cubed.eu",
  "*.azure.com",
  "luminati.io",
  "dspace.bracu.ac.bd",
  "github.githubassets.com",
  "googletagmanager.com",
  "archive.interconf.center",
  "osgeo.org",
  "novami.com",
  "deepblue.lib.umich.edu",
  "jamris.org",
  "researchportal.hw.ac.uk",
  "*.amap.com",
  "www.npmjs.com",
  "cdn.aaai.org",
  "yandy-ager.com",
  "jastt.org",
  "jonathansarwono.info",
  "*.sciencedirectassets.com",
  "journals.lww.com",
  "asprs.org",
  "*.epfl.ch",
  "e-tarjome.com",
  "essopenarchive.org",
  "journals.ashs.org",
  "*.google.com",
  "revues.imist.ma",
  "helper.ipam.ucla.edu",
  "ojs.unud.ac.id",
  "pubs.rsna.org",
  "*.newrelic.com",
  "lgincdnvzeuno.azureedge.net",
  "jscholarship.library.jhu.edu",
  "library.imaging.org",
  "ijcs.net",
  "jtec.utem.edu.my",
  "elgaronline.com",
  "lib.iitta.gov.ua",
  "asmedigitalcollection.asme.org",
  "caws.org.nz",
  "meeting.qq.com",
  "eviva-ml.github.io",
  "openjournals.uwaterloo.ca",
  "seaver-faculty.pepperdine.edu",
  "kimi.com",
  "elsevier.com",
  "mermaid.js.org",
  "ica-abs.copernicus.org",
  "tud.qucosa.de",
  "pure.york.ac.uk",
  "ojs.aaai.org",
  "yangli-feasibility.com",
  "ir.uitm.edu.my",
  "vldb.org",
  "research.ed.ac.uk",
  "davis-group-quantum-matter-research.ie",
  "jurnal.polgan.ac.id",
  "research-repository.griffith.edu.au",
  "examples.rpkg.net",
  "real.mtak.hu",
  "cs.cornell.edu",
  "www2.eecs.berkeley.edu",
  "jmlr.org",
  "bioone.org",
  "mljar.com",
  "klein.mit.edu",
  "*.pymc.io",
  "dam-oclc.bac-lac.gc.ca",
  "*.126.net",
  "scientific.net",
  "3.8.6.95",
  "search.ebscohost.com",
  "researchonline.ljmu.ac.uk",
  "journal.stekom.ac.id",
  "*.ieee.org",
  "dspace.mit.edu",
  "*.yeepay.com",
  "dl.begellhouse.com",
  "zlxb.zafu.edu.cn",
  "cs.ucy.ac.cy",
  "*.itch.io",
  "alvinang.sg",
  "rigeo.org",
  "dlib.org",
  "ojs.bonviewpress.com",
  "aisel.aisnet.org",
  "revistas.ucc.edu.co",
  "rshare.library.torontomu.ca",
  "repository.fit.edu",
  "acnsci.org",
  "4spepublications.onlinelibrary.wiley.com",
  "etda.libraries.psu.edu",
  "sure.sunderland.ac.uk",
  "ngcc.cn",
  "kresttechnology.com",
  "muroran-it.repo.nii.ac.jp",
  "research.google",
  "*.rsc.org",
  "norma.ncirl.ie",
  "pnas.org",
  "aaai.org",
  "arxiv.com",
  "*.clarivate.com",
  "semanticscholar.org",
  "*.cgiar.org",
  "microbiologyresearch.org",
  "coursesteach.com",
  "mesopotamian.press",
  "researchjournalnmit.wordpress.com",
  "opus.bibliothek.uni-augsburg.de",
  "repo.uni-hannover.de",
  "wiley.com",
  "aivc.org",
  "*.strongtech.org",
 "tools.strongvpn.asia",
  "biodiversity-science.net",
  "upcommons.upc.edu",
  "*.jquery.com",
  "builds.libav.org",
  "isprs.org",
  "indexinvestorportfolios.com",
  "klab.tch.harvard.edu",
  "bayesiancomputationbook.com",
  "*.cloudflareinsights.com",
  "scholarworks.umass.edu"
];


const blockedUrls = [
  "*://www.google.com/search*",
  ".*firefox.*",
  ".*firefox",
  "*://camo.githubusercontent.com/*" // 用于阻止包含“firefox”的 URL 的正则表达式
];

const onBeforeRequest = (details) => {
  const url = new URL(details.url);
  const host = url.hostname;

  // 检查是否在被阻止的 URL 列表中
  const isBlocked = blockedUrls.some(pattern => {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(details.url); // 检查整个 URL
  });

  if (isBlocked) {
    console.log(`Blocked URL: ${details.url}`);
    return { cancel: true }; // 拦截请求
  }

  // 检查是否在允许的 URL 列表中
  const isAllowed = allowedUrls.some(pattern => {
    // 处理通配符
    if (pattern.startsWith("*.") && host.endsWith(pattern.slice(2))) {
      return true;
    }
    return host === pattern || host === 'www.' + pattern; // 检查主机名
  });

  if (!isAllowed) {
    console.log(`Blocked URL: ${details.url}`);
    return { cancel: true }; // 拦截请求
  }

  return { cancel: false }; // 允许请求
};

// 监听所有请求
browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: ["<all_urls>"] },
  ["blocking"]
);
