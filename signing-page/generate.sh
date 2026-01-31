#!/bin/bash
# Generate a signing page with pre-filled decrypt credentials
#
# Usage:
#   ./generate.sh --decrypt-message <message> --user-encrypted <hex> [--output <file>]
#
# This creates an index.html with the values embedded, ready for build.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="$SCRIPT_DIR/index.html"

DECRYPT_MESSAGE=""
USER_ENCRYPTED=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--decrypt-message)
            DECRYPT_MESSAGE="$2"
            shift 2
            ;;
        -e|--user-encrypted)
            USER_ENCRYPTED="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 --decrypt-message <message> --user-encrypted <hex>"
            echo ""
            echo "Options:"
            echo "  -m, --decrypt-message  Message user signs to derive decryption key"
            echo "  -e, --user-encrypted   Encrypted connection details (hex)"
            echo "  -o, --output           Output file (default: index.html)"
            echo "  -h, --help             Show this help"
            echo ""
            echo "Example:"
            echo "  $0 -m 'Decrypt BlockHost credentials' -e 'a1b2c3d4...'"
            echo "  ./build.sh  # Then run build.sh to base64 encode"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check required parameters
if [ -z "$DECRYPT_MESSAGE" ]; then
    echo "Error: --decrypt-message is required"
    exit 1
fi

if [ -z "$USER_ENCRYPTED" ]; then
    echo "Error: --user-encrypted is required"
    exit 1
fi

# Escape special characters for sed
escape_sed() {
    echo "$1" | sed 's/[&/\]/\\&/g'
}

DECRYPT_MESSAGE_ESC=$(escape_sed "$DECRYPT_MESSAGE")
USER_ENCRYPTED_ESC=$(escape_sed "$USER_ENCRYPTED")

cat > "$OUTPUT" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web3 Auth</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.c{max-width:480px;width:100%;background:#1a1a1a;border-radius:12px;padding:24px;box-shadow:0 4px 24px rgba(0,0,0,.5)}
h1{font-size:1.25rem;margin-bottom:16px;color:#fff}
label{display:block;margin-bottom:6px;font-size:.875rem;color:#888}
input,textarea{width:100%;padding:12px;border:1px solid #333;border-radius:8px;background:#0a0a0a;color:#fff;font-size:1rem;margin-bottom:16px;font-family:inherit}
textarea{resize:vertical;min-height:80px;font-family:monospace;font-size:.75rem}
input:focus,textarea:focus{outline:none;border-color:#3b82f6}
button{width:100%;padding:12px;border:none;border-radius:8px;font-size:1rem;cursor:pointer;transition:background .2s}
.btn-primary{background:#3b82f6;color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-primary:disabled{background:#1e3a5f;cursor:not-allowed}
.btn-secondary{background:#4b5563;color:#fff;margin-top:8px}
.btn-secondary:hover{background:#374151}
.btn-copy{background:#22c55e;color:#fff;margin-top:8px}
.btn-copy:hover{background:#16a34a}
.result{margin-top:16px;padding:12px;background:#0a0a0a;border-radius:8px;word-break:break-all;font-family:monospace;font-size:.75rem;max-height:120px;overflow-y:auto}
.status{text-align:center;padding:8px;margin-bottom:16px;border-radius:6px;font-size:.875rem}
.status.error{background:#7f1d1d;color:#fca5a5}
.status.success{background:#14532d;color:#86efac}
.hidden{display:none}
.wallet{font-size:.75rem;color:#666;margin-bottom:16px;word-break:break-all}
.info{font-size:.75rem;color:#888;margin-bottom:16px;line-height:1.5}

/* Tabs */
.tabs{display:flex;margin-bottom:16px;border-bottom:1px solid #333}
.tab{flex:1;padding:12px;text-align:center;cursor:pointer;color:#888;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:#e0e0e0}
.tab.active{color:#3b82f6;border-bottom-color:#3b82f6}
.tab-content{display:none}
.tab-content.active{display:block}
</style>
</head>
<body>
<div class="c">
<h1>Web3 Authentication</h1>
<div id="status" class="status hidden"></div>

<div id="connect-section">
<p class="info">Sign in to your server using your Ethereum wallet. Connect your wallet to get started.</p>
<button id="connect" class="btn-primary">Connect Wallet</button>
</div>

<div id="main-section" class="hidden">
<div id="wallet" class="wallet"></div>

<!-- Tabs -->
<div class="tabs">
<div class="tab active" data-tab="sign">Sign OTP</div>
<div class="tab" data-tab="decrypt">Decrypt Access</div>
</div>

<!-- Sign OTP Tab -->
<div id="tab-sign" class="tab-content active">
<div id="sign-form">
<label for="code">Enter OTP Code</label>
<input type="text" id="code" placeholder="123456" maxlength="8" autocomplete="off">
<label for="machine">Machine ID</label>
<input type="text" id="machine" placeholder="server-prod-01" autocomplete="off">
<button id="sign" class="btn-primary">Sign Message</button>
</div>

<div id="sign-result" class="hidden">
<label>Signature (paste this in terminal)</label>
<div id="sig" class="result"></div>
<button id="copy-sig" class="btn-copy">Copy to Clipboard</button>
<button id="reset-sign" class="btn-secondary">Sign Another</button>
</div>
</div>

<!-- Decrypt Access Tab -->
<div id="tab-decrypt" class="tab-content">
<p class="info">Decrypt your NFT access credentials. You'll sign a message to derive your decryption key.</p>

<div id="decrypt-form">
<label for="decrypt-msg">Decrypt Message (from NFT)</label>
<input type="text" id="decrypt-msg" placeholder="libpam-web3:0x...:nonce" autocomplete="off">
<label for="encrypted-data">Encrypted Data (from NFT)</label>
<textarea id="encrypted-data" placeholder="Paste the encrypted connection details from your NFT"></textarea>
<button id="decrypt-btn" class="btn-primary">Decrypt</button>
</div>

<div id="decrypt-result" class="hidden">
<label>Decrypted Data</label>
<div id="decrypted" class="result"></div>
<button id="copy-decrypted" class="btn-copy">Copy to Clipboard</button>
<button id="reset-decrypt" class="btn-secondary">Decrypt Another</button>
</div>
</div>
</div>
</div>

<script>
(function(){
const CONFIG={
    decryptMessage:'__DECRYPT_MESSAGE__',
    userEncrypted:'__USER_ENCRYPTED__'
};

let addr='';
const $=id=>document.getElementById(id);
const show=(id,v=true)=>$(id).classList.toggle('hidden',!v);
const status=(msg,type='success')=>{const s=$('status');s.textContent=msg;s.className='status '+type;show('status')};

// Tab switching
document.querySelectorAll('.tab').forEach(tab=>{
    tab.onclick=()=>{
        document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
        tab.classList.add('active');
        $('tab-'+tab.dataset.tab).classList.add('active');
        show('status',false);
    };
});

// Pre-fill decrypt fields if configured (and make read-only)
if(CONFIG.decryptMessage && CONFIG.decryptMessage !== '__DECRYPT_MESSAGE__'){
    $('decrypt-msg').value = CONFIG.decryptMessage;
    $('decrypt-msg').readOnly = true;
    $('decrypt-msg').style.opacity = '0.7';
}
if(CONFIG.userEncrypted && CONFIG.userEncrypted !== '__USER_ENCRYPTED__'){
    $('encrypted-data').value = CONFIG.userEncrypted;
    $('encrypted-data').readOnly = true;
    $('encrypted-data').style.opacity = '0.7';
}

async function connect(){
    if(!window.ethereum){status('No wallet found. Install MetaMask.','error');return}
    try{
        const accs=await window.ethereum.request({method:'eth_requestAccounts'});
        addr=accs[0];
        $('wallet').textContent='Connected: '+addr;
        show('connect-section',false);
        show('main-section');
        show('status',false);
    }catch(e){status('Connection rejected','error')}
}

// === Sign OTP ===
async function sign(){
    const code=$('code').value.trim();
    const machine=$('machine').value.trim();
    if(!code){status('Enter OTP code','error');return}
    if(!machine){status('Enter machine ID','error');return}
    const msg='Authenticate to '+machine+' with code: '+code;
    try{
        $('sign').disabled=true;
        $('sign').textContent='Signing...';
        const sig=await window.ethereum.request({method:'personal_sign',params:[msg,addr]});
        $('sig').textContent=sig;
        show('sign-form',false);
        show('sign-result');
        status('Signed successfully! Copy and paste below.','success');
    }catch(e){
        status('Signing failed: '+e.message,'error');
    }finally{
        $('sign').disabled=false;
        $('sign').textContent='Sign Message';
    }
}

function resetSign(){
    show('sign-form');
    show('sign-result',false);
    $('code').value='';
    show('status',false);
}

// === Decrypt Access ===
async function decrypt(){
    const decryptMsg=$('decrypt-msg').value.trim();
    const encryptedData=$('encrypted-data').value.trim();
    if(!decryptMsg){status('Enter decrypt message','error');return}
    if(!encryptedData){status('Enter encrypted data','error');return}

    try{
        $('decrypt-btn').disabled=true;
        $('decrypt-btn').textContent='Signing...';

        // Sign the decrypt message to derive key
        const sig=await window.ethereum.request({method:'personal_sign',params:[decryptMsg,addr]});

        // Derive key from signature using keccak256
        const key=keccak256(sig);

        // Decrypt the data
        const decrypted=await decryptAesGcm(key,encryptedData);

        $('decrypted').textContent=decrypted;
        show('decrypt-form',false);
        show('decrypt-result');
        status('Decrypted successfully!','success');
    }catch(e){
        status('Decryption failed: '+e.message,'error');
    }finally{
        $('decrypt-btn').disabled=false;
        $('decrypt-btn').textContent='Decrypt';
    }
}

function resetDecrypt(){
    show('decrypt-form');
    show('decrypt-result',false);
    $('decrypt-msg').value='';
    $('encrypted-data').value='';
    show('status',false);
}

// Keccak256 implementation
function keccak256(input){
    const RC=[1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,
        0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,
        0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
        0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,
        0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
    const ROTC=[1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44];
    const PI=[10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1];
    const rotl=(x,n)=>((x<<BigInt(n))|(x>>BigInt(64-n)))&0xffffffffffffffffn;

    function keccakF(s){
        for(let r=0;r<24;r++){
            let c=[0n,0n,0n,0n,0n];
            for(let x=0;x<5;x++)c[x]=s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20];
            for(let x=0;x<5;x++){let t=c[(x+4)%5]^rotl(c[(x+1)%5],1);for(let y=0;y<25;y+=5)s[x+y]^=t;}
            let t=s[1];for(let i=0;i<24;i++){let j=PI[i];let tmp=s[j];s[j]=rotl(t,ROTC[i]);t=tmp;}
            for(let y=0;y<25;y+=5){let t0=s[y],t1=s[y+1];s[y]^=(~t1)&s[y+2];s[y+1]^=(~s[y+2])&s[y+3];s[y+2]^=(~s[y+3])&s[y+4];s[y+3]^=(~s[y+4])&t0;s[y+4]^=(~t0)&t1;}
            s[0]^=RC[r];
        }
    }

    // Convert hex string to bytes
    let msg;
    if(input.startsWith('0x')){
        input=input.slice(2);
        msg=new Uint8Array(input.length/2);
        for(let i=0;i<input.length;i+=2)msg[i/2]=parseInt(input.substr(i,2),16);
    }else{
        msg=new TextEncoder().encode(input);
    }

    const rate=136;
    let padded=new Uint8Array(Math.ceil((msg.length+1)/rate)*rate);
    padded.set(msg);
    padded[msg.length]=0x01;
    padded[padded.length-1]|=0x80;

    let s=new Array(25).fill(0n);
    for(let i=0;i<padded.length;i+=rate){
        for(let j=0;j<rate/8;j++){
            let v=0n;
            for(let k=0;k<8;k++)v|=BigInt(padded[i+j*8+k])<<BigInt(k*8);
            s[j]^=v;
        }
        keccakF(s);
    }

    let out=new Uint8Array(32);
    for(let i=0;i<4;i++){
        for(let j=0;j<8;j++){
            out[i*8+j]=Number((s[i]>>BigInt(j*8))&0xffn);
        }
    }
    return out;
}

// AES-GCM decryption
async function decryptAesGcm(keyBytes,ciphertextHex){
    // Parse hex: first 12 bytes = nonce, rest = ciphertext
    ciphertextHex=ciphertextHex.replace(/^0x/,'');
    const data=new Uint8Array(ciphertextHex.length/2);
    for(let i=0;i<ciphertextHex.length;i+=2)data[i/2]=parseInt(ciphertextHex.substr(i,2),16);

    const nonce=data.slice(0,12);
    const ciphertext=data.slice(12);

    const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']);
    const decrypted=await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce},key,ciphertext);
    return new TextDecoder().decode(decrypted);
}

// Copy utilities
function copy(id,btnId){
    navigator.clipboard.writeText($(id).textContent).then(()=>{
        const btn=$(btnId);
        const orig=btn.textContent;
        btn.textContent='Copied!';
        setTimeout(()=>btn.textContent=orig,2000);
    });
}

// Event listeners
$('connect').onclick=connect;
$('sign').onclick=sign;
$('copy-sig').onclick=()=>copy('sig','copy-sig');
$('reset-sign').onclick=resetSign;
$('decrypt-btn').onclick=decrypt;
$('copy-decrypted').onclick=()=>copy('decrypted','copy-decrypted');
$('reset-decrypt').onclick=resetDecrypt;
$('code').onkeypress=e=>{if(e.key==='Enter')$('machine').focus()};
$('machine').onkeypress=e=>{if(e.key==='Enter')sign()};

// Auto-connect if already connected
if(window.ethereum&&window.ethereum.selectedAddress){
    addr=window.ethereum.selectedAddress;
    $('wallet').textContent='Connected: '+addr;
    show('connect-section',false);
    show('main-section');
}
})();
</script>
</body>
</html>
HTMLEOF

# Replace placeholders with actual values
sed -i "s|__DECRYPT_MESSAGE__|$DECRYPT_MESSAGE_ESC|g" "$OUTPUT"
sed -i "s|__USER_ENCRYPTED__|$USER_ENCRYPTED_ESC|g" "$OUTPUT"

echo "Generated: $OUTPUT"
echo "Decrypt message: $DECRYPT_MESSAGE"
echo "User encrypted:  ${USER_ENCRYPTED:0:40}..."
echo ""
echo "Run ./build.sh to create base64-encoded version for NFT minting."
