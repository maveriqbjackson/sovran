/* sv-crypto.js — shared client-side crypto for SOVRAN accounts.
   Everything here runs in the browser. The dataKey never leaves it. */
(function(){
'use strict';
var enc=new TextEncoder(), dec=new TextDecoder();

function b64(buf){var b=new Uint8Array(buf),s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
function unb64(s){var bin=atob(s),a=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return a;}

// 600,000 PBKDF2 iterations — the current OWASP guidance for PBKDF2-SHA256.
// Slow on purpose: it is what makes a stolen hash expensive to attack.
var ITER=600000;

async function derive(passphrase, salt, purpose, asBits){
  var base=await crypto.subtle.importKey('raw',enc.encode(passphrase),'PBKDF2',false,['deriveBits','deriveKey']);
  var params={name:'PBKDF2',salt:enc.encode(purpose+'|'+salt),iterations:ITER,hash:'SHA-256'};
  if(asBits) return b64(await crypto.subtle.deriveBits(params,base,256));
  return crypto.subtle.deriveKey(params,base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}

// sent to the server — proves identity, useless for decryption
function authKey(passphrase,salt){ return derive(passphrase,salt,'sovran-auth',true); }
// never sent anywhere — encrypts the vault
function dataKey(passphrase,salt){ return derive(passphrase,salt,'sovran-data',false); }

async function encrypt(key,obj){
  var iv=crypto.getRandomValues(new Uint8Array(12));
  var ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key,enc.encode(JSON.stringify(obj)));
  return {ciphertext:b64(ct),iv:b64(iv)};
}
async function decrypt(key,ciphertext,iv){
  var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv)},key,unb64(ciphertext));
  return JSON.parse(dec.decode(pt));
}

function api(action,payload){
  return fetch('/api/account',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(Object.assign({action:action},payload||{}))
  }).then(function(r){ return r.json().then(function(d){ return {ok:r.ok,d:d}; }); });
}

window.SV = {authKey:authKey, dataKey:dataKey, encrypt:encrypt, decrypt:decrypt, api:api, ITER:ITER};
})();
