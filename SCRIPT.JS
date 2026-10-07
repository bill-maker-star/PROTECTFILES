// --------------- UI Helpers ---------------

function openTab(tabId) {
  const target = document.getElementById(tabId);
  if (!target) return;

  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });

  target.classList.add('active');

  const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  if (btn) {
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
  }
}

function setStatus(id, message, type = 'neutral'){
  const el = typeof id === 'string' ? document.getElementById(id) : id;
  if (!el) return;
  el.textContent = message;
  el.classList.remove('status-neutral', 'status-progress', 'status-success', 'status-error');
  el.classList.add(`status-${type}`);
}

function downloadBlob(blob, filename){
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function ensureCryptoSupport(){
  if (!window.crypto?.subtle) {
    throw new Error('Secure crypto APIs are not available in this browser.');
  }
}

// --------------- Crypto Helpers (PBKDF2 + AES-GCM) ---------------

const APP_SALT_TEXT = 'EncFileVaultSalt';
const APP_IV_LENGTH = 12;
const LEGACY_WEB_SALT_LENGTH = 16;

async function deriveKey(password, salt){
  ensureCryptoSupport();
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    {name:'PBKDF2'},
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' },
    keyMaterial,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

function getAppSalt(){
  return new TextEncoder().encode(APP_SALT_TEXT);
}

function concatU8(...arrays){
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const o = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays){
    o.set(item, offset);
    offset += item.length;
  }
  return o;
}

// Android app compatible format:
// [iv(12)][ciphertext + GCM tag], key = PBKDF2WithHmacSHA256(password, "EncFileVaultSalt", 100000, 256)
async function encryptBytes(plainU8, password){
  const iv = crypto.getRandomValues(new Uint8Array(APP_IV_LENGTH));
  const key = await deriveKey(password, getAppSalt());
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, plainU8)
  );
  return concatU8(iv, cipher);
}

async function decryptBytes(encU8, password){
  if (encU8.length < APP_IV_LENGTH + 16) throw new Error('Data too small');
  const iv = encU8.slice(0, APP_IV_LENGTH);
  const ct = encU8.slice(APP_IV_LENGTH);
  const key = await deriveKey(password, getAppSalt());
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct)
  );
  return plain;
}

// Backward compatibility for files made by older v3 web builds:
// [salt(16)][iv(12)][ciphertext + GCM tag]
async function decryptLegacyWebBytes(encU8, password){
  if (encU8.length < LEGACY_WEB_SALT_LENGTH + APP_IV_LENGTH + 16) {
    throw new Error('Data too small');
  }
  const salt = encU8.slice(0, LEGACY_WEB_SALT_LENGTH);
  const iv = encU8.slice(LEGACY_WEB_SALT_LENGTH, LEGACY_WEB_SALT_LENGTH + APP_IV_LENGTH);
  const ct = encU8.slice(LEGACY_WEB_SALT_LENGTH + APP_IV_LENGTH);
  const key = await deriveKey(password, salt);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct)
  );
  return plain;
}

async function decryptBytesWithFallback(encU8, password){
  try{
    return await decryptBytes(encU8, password);
  }catch(appErr){
    try{
      return await decryptLegacyWebBytes(encU8, password);
    }catch(legacyErr){
      throw appErr;
    }
  }
}

// --------------- File Protector ---------------

function readFileAsArrayBuffer(file){
  return new Promise((res,rej)=>{
    const fr=new FileReader();
    fr.onload=e=>res(e.target.result);
    fr.onerror=()=>rej(new Error('Read error'));
    fr.readAsArrayBuffer(file);
  });
}

// Encrypt file: direct download
async function encryptFile(){
  const f = document.getElementById('file-encrypt-input').files[0];
  const pwd = document.getElementById('file-encrypt-key').value;
  if (!f || !pwd) return alert('Select file and enter password');

  try{
    setStatus('file-encrypt-status', 'Encrypting file...', 'progress');
    const buf = await readFileAsArrayBuffer(f);
    const enc = await encryptBytes(new Uint8Array(buf), pwd);
    const blob = new Blob([enc], { type:'application/octet-stream' });
    downloadBlob(blob, `${f.name}.enc`);
    setStatus('file-encrypt-status', 'File encrypted and downloaded successfully.', 'success');
  }catch(e){
    setStatus('file-encrypt-status', `Error: ${e.message}`, 'error');
  }
}

// Temporary decrypted preview state
let lastDecryptedUrl = null;

// Decrypt file: PREVIEW + FULLSCREEN + DOWNLOAD BUTTON
async function decryptFile(){
  const f = document.getElementById('file-decrypt-input').files[0];
  const pwd = document.getElementById('file-decrypt-key').value;

  const previewBox = document.getElementById('file-preview-container');
  const frame = document.getElementById('file-preview-frame');
  const dlBtn = document.getElementById('file-download-btn');

  if (!f || !pwd) return alert('Select encrypted file and enter password');

  try{
    setStatus('file-decrypt-status', 'Decrypting file...', 'progress');
    previewBox.hidden = true;

    const buf = await readFileAsArrayBuffer(f);
    const plain = await decryptBytesWithFallback(new Uint8Array(buf), pwd);

    // Revoke previous URL
    if (lastDecryptedUrl){
      URL.revokeObjectURL(lastDecryptedUrl);
      lastDecryptedUrl = null;
    }

    // Simple MIME guess by extension (common photo / video / pdf)
    let mime = 'application/octet-stream';
    const name = f.name.toLowerCase();

    // Text / HTML / PDF
    if (name.endsWith('.txt.enc')) mime = 'text/plain';
    else if (name.endsWith('.html.enc') || name.endsWith('.htm.enc')) mime = 'text/html';
    else if (name.endsWith('.pdf.enc')) mime = 'application/pdf';

    // Images (photos)
    else if (name.endsWith('.png.enc')) mime = 'image/png';
    else if (name.endsWith('.jpg.enc') || name.endsWith('.jpeg.enc')) mime = 'image/jpeg';
    else if (name.endsWith('.gif.enc')) mime = 'image/gif';
    else if (name.endsWith('.webp.enc')) mime = 'image/webp';
    else if (name.endsWith('.bmp.enc')) mime = 'image/bmp';
    else if (name.endsWith('.svg.enc')) mime = 'image/svg+xml';

    // Videos (popular)
    else if (name.endsWith('.mp4.enc')) mime = 'video/mp4';
    else if (name.endsWith('.webm.enc')) mime = 'video/webm';
    else if (name.endsWith('.ogg.enc') || name.endsWith('.ogv.enc')) mime = 'video/ogg';
    else if (name.endsWith('.mov.enc')) mime = 'video/quicktime';
    else if (name.endsWith('.mkv.enc')) mime = 'video/x-matroska';
    else if (name.endsWith('.avi.enc')) mime = 'video/x-msvideo';
    else if (name.endsWith('.3gp.enc') || name.endsWith('.3g2.enc')) mime = 'video/3gpp';

    // Audio (optional but useful)
    else if (name.endsWith('.mp3.enc')) mime = 'audio/mpeg';
    else if (name.endsWith('.wav.enc')) mime = 'audio/wav';
    else if (name.endsWith('.oga.enc') || name.endsWith('.ogg.enc')) mime = 'audio/ogg';
    else if (name.endsWith('.m4a.enc')) mime = 'audio/mp4';

    const blob = new Blob([plain], { type: mime });
    const url = URL.createObjectURL(blob);
    lastDecryptedUrl = url;

    // Preview
    frame.src = url;
    previewBox.hidden = false;

    // Download only on click
    const downloadName = f.name.replace(/\.enc$/i,'') || 'decrypted.bin';
    dlBtn.onclick = () => {
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadName;
      a.click();
    };

    setStatus('file-decrypt-status', 'File decrypted. Preview is ready below.', 'success');
  }catch(e){
    setStatus('file-decrypt-status', `Error: ${e.message}`, 'error');
  }
}

// --------------- Folder Protector (Folder or ZIP input) ---------------

const MAX_TOTAL_SIZE = 1024 * 1024 * 1024; // 1 GB
let encZipUrl=null, encZipName=null, decZipUrl=null, decZipName=null;

function onEncSourceTypeChange(){
  const mode = document.getElementById('enc-source-type').value;
  document.getElementById('enc-folder-wrap').hidden = mode !== 'folder';
  document.getElementById('enc-zip-wrap').hidden = mode !== 'zip';
}

function getRootFolderName(files){
  const p = files[0].webkitRelativePath || files[0].name || 'FOLDER';
  return p.split('/')[0] || 'FOLDER';
}

function sanitizePath(p){
  const cleaned = String(p || '')
    .replace(/\\/g, '/')
    .split('/')
    .map(part => part.trim())
    .filter(part => part && part !== '.' && part !== '..')
    .map(part => part.replace(/[:*?"<>|]/g, '_'));

  if (!cleaned.length) {
    throw new Error('Encountered an unsafe or empty file path in the archive.');
  }

  return cleaned.join('/');
}

async function addEncryptedFileToZip(zipFolder, pathInZip, arrayBuffer, password){
  const encU8 = await encryptBytes(new Uint8Array(arrayBuffer), password);
  zipFolder.file(pathInZip + '.enc', encU8, { binary:true });
}

async function encryptFolderOrZip(){
  const mode = document.getElementById('enc-source-type').value;
  const pwd = document.getElementById('enc-folder-key').value;
  const out = document.getElementById('enc-folder-output');
  const btn = document.getElementById('enc-folder-btn');
  const dl  = document.getElementById('download-enc-zip-btn');

  if (!pwd) return alert('Enter password');

  btn.disabled = true;
  dl.hidden = true;
  setStatus(out, 'Processing archive encryption...', 'progress');

  if (encZipUrl) URL.revokeObjectURL(encZipUrl);

  try{
    const JSZipRef = window.JSZip;
    if (!JSZipRef) throw new Error('JSZip not loaded');

    const zip = new JSZipRef();

    if (mode === 'folder'){
      const files = document.getElementById('enc-folder-input').files;
      if (!files.length) throw new Error('Select a folder');

      const root = getRootFolderName(files);
      const encRoot = zip.folder(`${root}_ENC`);
      let total=0;

      for (const file of files){
        const rel = file.webkitRelativePath
          ? file.webkitRelativePath.split('/').slice(1).join('/')
          : file.name;
        const norm = sanitizePath(rel);
        const buf = await readFileAsArrayBuffer(file);
        total += buf.byteLength;
        if (total > MAX_TOTAL_SIZE) throw new Error('Total exceeds 1 GB');
        await addEncryptedFileToZip(encRoot, norm, buf, pwd);
      }

      const blob = await zip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
      encZipUrl = URL.createObjectURL(blob);
      encZipName = `${root}_ENC.zip`;
    } else {
      // mode === 'zip'
      const zfile = document.getElementById('enc-zip-input').files[0];
      if (!zfile) throw new Error('Select a ZIP file');

      const inBuf = await readFileAsArrayBuffer(zfile);
      const inZip = await JSZipRef.loadAsync(inBuf);
      const base = zfile.name.replace(/\.zip$/i,'');

      const encRoot = zip.folder(`${base}_ENC`);
      let total=0;

      for (const [path, zf] of Object.entries(inZip.files)){
        if (zf.dir) continue;
        const u8 = new Uint8Array(await zf.async('uint8array'));
        total += u8.byteLength;
        if (total > MAX_TOTAL_SIZE) throw new Error('Total exceeds 1 GB');
        await addEncryptedFileToZip(encRoot, sanitizePath(path), u8.buffer, pwd);
      }

      const blob = await zip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
      encZipUrl = URL.createObjectURL(blob);
      encZipName = `${base}_ENC.zip`;
    }

    setStatus(out, `Encrypted archive ready: ${encZipName}`, 'success');
    dl.hidden = false;
  }catch(e){
    setStatus(out, `Error: ${e.message}`, 'error');
  }finally{
    btn.disabled = false;
  }
}

function downloadEncZip(){
  if (!encZipUrl || !encZipName) return alert('No encrypted ZIP available');
  const a=document.createElement('a');
  a.href=encZipUrl;
  a.download=encZipName;
  a.click();
}

async function decryptFolderOrZip(){
  const mode = document.getElementById('dec-source-type').value; // 'enczip' or 'zip'
  const pwd = document.getElementById('dec-folder-key').value;
  const zinput = document.getElementById('dec-zip-input');
  const out = document.getElementById('dec-folder-output');
  const btn = document.getElementById('dec-folder-btn');
  const dl  = document.getElementById('download-dec-zip-btn');

  if (!zinput.files.length) return alert('Select a ZIP file');
  if (!pwd) return alert('Enter password');

  btn.disabled = true;
  dl.hidden = true;
  setStatus(out, 'Processing archive decryption...', 'progress');

  if (decZipUrl) URL.revokeObjectURL(decZipUrl);

  try{
    const JSZipRef = window.JSZip;
    if (!JSZipRef) throw new Error('JSZip not loaded');

    const inBuf = await readFileAsArrayBuffer(zinput.files[0]);
    const inZip = await JSZipRef.loadAsync(inBuf);
    const outZip = new JSZipRef();

    // Detect ENC root like "X_ENC/"
    let encRootFolder = null;
    Object.keys(inZip.files).forEach(k => {
      if (inZip.files[k].dir && /_ENC\/$/i.test(k)) encRootFolder = k;
    });

    const inBase = zinput.files[0].name.replace(/\.zip$/i,'');
    let outRoot;

    if (mode === 'enczip' || encRootFolder){
      const root = encRootFolder || `${inBase}/`;
      outRoot = root.replace(/_ENC\/?$/i,'/');
    } else {
      outRoot = `${inBase}_DECRYPTED/`;
    }

    let totalPlain = 0;

    for (const [path, zf] of Object.entries(inZip.files)){
      if (zf.dir) continue;
      let rel = path;
      if (encRootFolder && path.startsWith(encRootFolder)) rel = path.slice(encRootFolder.length);
      if (!rel) continue;

      const u8 = new Uint8Array(await zf.async('uint8array'));

      if (/\.enc$/i.test(rel)){
        // decrypt
        let plain;
        try{
          plain = await decryptBytesWithFallback(u8, pwd);
        }catch(err){
          throw new Error(`Wrong password or corrupted file: ${rel}`);
        }
        totalPlain += plain.byteLength;
        if (totalPlain > MAX_TOTAL_SIZE) throw new Error('Decrypted total exceeds 1 GB');
        const cleanPath = rel.replace(/\.enc$/i,'');
        outZip.file(`${outRoot}${sanitizePath(cleanPath)}`, plain, { binary:true });
      } else {
        // copy as-is
        totalPlain += u8.byteLength;
        if (totalPlain > MAX_TOTAL_SIZE) throw new Error('Output total exceeds 1 GB');
        outZip.file(`${outRoot}${sanitizePath(rel)}`, u8, { binary:true });
      }
    }

    const blob = await outZip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
    decZipUrl = URL.createObjectURL(blob);
    const decBase = encRootFolder ? inBase.replace(/_ENC$/i,'') : inBase;
    decZipName = `${decBase}_DECRYPTED.zip`;

    setStatus(out, `Decrypted archive ready: ${decZipName}`, 'success');
    dl.hidden = false;
  }catch(e){
    setStatus(out, `Decryption failed: ${e.message}`, 'error');
  }finally{
    btn.disabled = false;
  }
}

function downloadDecZip(){
  if (!decZipUrl || !decZipName) return alert('No decrypted ZIP available');
  const a=document.createElement('a');
  a.href=decZipUrl;
  a.download=decZipName;
  a.click();
}

// --------------- Preview Fullscreen + Clear (temporary data) ---------------

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => openTab(btn.dataset.tab));
  });

  document.getElementById('file-encrypt-btn')?.addEventListener('click', encryptFile);
  document.getElementById('file-decrypt-btn')?.addEventListener('click', decryptFile);
  document.getElementById('enc-folder-btn')?.addEventListener('click', encryptFolderOrZip);
  document.getElementById('dec-folder-btn')?.addEventListener('click', decryptFolderOrZip);
  document.getElementById('download-enc-zip-btn')?.addEventListener('click', downloadEncZip);
  document.getElementById('download-dec-zip-btn')?.addEventListener('click', downloadDecZip);
  document.getElementById('enc-source-type')?.addEventListener('change', onEncSourceTypeChange);

  const frame     = document.getElementById('file-preview-frame');
  const fullBtn   = document.getElementById('file-preview-full-btn');
  const clearBtn  = document.getElementById('file-clear-btn');
  const previewBox= document.getElementById('file-preview-container');

  if (fullBtn && frame){
    fullBtn.onclick = () => {
      if (frame.requestFullscreen) {
        frame.requestFullscreen();
      } else if (frame.webkitRequestFullscreen) {
        frame.webkitRequestFullscreen();
      } else {
        alert('Fullscreen not supported in this browser.');
      }
    };
  }

  if (clearBtn && frame && previewBox){
    clearBtn.onclick = () => {
      if (lastDecryptedUrl){
        URL.revokeObjectURL(lastDecryptedUrl);
        lastDecryptedUrl = null;
      }
      frame.src = 'about:blank';
      previewBox.hidden = true;
      setStatus('file-decrypt-status', 'Preview cleared. Ready for another file.', 'neutral');
      const finput = document.getElementById('file-decrypt-input');
      const fpwd   = document.getElementById('file-decrypt-key');
      if (finput) finput.value = '';
      if (fpwd) fpwd.value = '';
    };
  }

  onEncSourceTypeChange();
});
