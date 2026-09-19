/* ─────────────────────────────────────────────────────────────
   SOVRAN — the Kickstarter switch.

   This is the only file you edit to put the campaign on the site.
   There are exactly three settings below and nothing else to touch.

   On launch day you change one word: false becomes true.
   Save it, upload this one file, hard-refresh. That is the whole job.

   The three settings mean:

     on      false  = the site never mentions Kickstarter at all.
             true   = the banner and the campaign section appear.

     stage   "prelaunch" = everything says "Follow".  Use this while
                           the page is up but the campaign has not opened.
             "live"      = everything says "Back it".  Use this once
                           the campaign is actually taking money.

     url     the campaign address. Already filled in.

   When the campaign finishes, set on back to false and it all
   disappears cleanly.
   ───────────────────────────────────────────────────────────── */

window.SV_KS = {

  on: false,

  stage: "prelaunch",

  url: "https://www.kickstarter.com/projects/maveriqbjackson/sovran-privacy-tools-that-never-learn-who-you-are"

};

/* Used by the pages. Returns null when there is nothing to show, so every
   page can bail out on one line. Guards against a half-finished edit. */
window.SV_KS.state = function () {
  var c = window.SV_KS;
  if (c.on !== true) return null;
  if (typeof c.url !== 'string') return null;
  if (c.url.indexOf('kickstarter.com/projects/') === -1) return null;
  return { url: c.url, live: c.stage === 'live' };
};
