(function() {
'use strict';

var addr = '';
var $ = function(id) { return document.getElementById(id); };
var sessionId = (new URLSearchParams(window.location.search)).get('session');

function showStatus(msg, type) {
    var el = $('status-message');
    el.textContent = msg;
    el.classList.remove('hidden', 'error', 'success');
    if (type) el.classList.add(type);
}

function hideStatus() {
    var el = $('status-message');
    el.classList.add('hidden');
    el.classList.remove('error', 'success');
}

async function connect() {
    if (!window.ethereum) {
        showStatus('No wallet found. Install MetaMask.', 'error');
        return;
    }
    var btn = $('btn-connect');
    try {
        btn.classList.add('loading');
        btn.textContent = 'Connecting...';

        var accs = await window.ethereum.request({ method: 'eth_requestAccounts' });
        addr = accs[0];
        $('wallet-address').textContent = 'Connected: ' + addr;
        $('step-connect').classList.add('hidden');
        $('step-sign').classList.remove('hidden');
        hideStatus();
        if (sessionId) await loadSession();
    } catch (e) {
        showStatus('Connection rejected', 'error');
        btn.classList.remove('loading');
        btn.textContent = 'Connect Wallet';
    }
}

async function loadSession() {
    try {
        var res = await fetch('/auth/pending/' + sessionId);
        if (!res.ok) return;
        var data = await res.json();
        if (data.otp) { $('code').value = data.otp; $('code').readOnly = true; }
        if (data.machine_id) { $('machine').value = data.machine_id; $('machine').readOnly = true; }
    } catch (e) { /* fall through to manual mode */ }
}

async function sign() {
    var code = $('code').value.trim();
    var machine = $('machine').value.trim();
    if (!code) { showStatus('Enter OTP code', 'error'); return; }
    if (!machine) { showStatus('Enter machine ID', 'error'); return; }
    var msg = 'Authenticate to ' + machine + ' with code: ' + code;
    var btn = $('btn-sign');
    try {
        btn.disabled = true;
        btn.classList.add('loading');
        btn.textContent = 'Signing...';

        var sig = await window.ethereum.request({ method: 'personal_sign', params: [msg, addr] });
        if (sessionId) {
            try {
                var cb = await fetch('/auth/callback/' + sessionId, { method: 'POST', body: sig });
                if (cb.ok) {
                    $('sign-form').classList.add('hidden');
                    $('sign-result').classList.add('hidden');
                    showStatus('Signature sent! Press Enter in your terminal.', 'success');
                    return;
                }
            } catch (e) { /* fall through to manual copy mode */ }
        }
        $('sig').textContent = sig;
        $('sign-form').classList.add('hidden');
        $('sign-result').classList.remove('hidden');
        showStatus('Signed successfully! Copy and paste below.', 'success');
    } catch (e) {
        showStatus('Signing failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.textContent = 'Sign Message';
    }
}

function resetSign() {
    $('sign-form').classList.remove('hidden');
    $('sign-result').classList.add('hidden');
    $('code').value = '';
    $('code').readOnly = false;
    $('machine').readOnly = false;
    hideStatus();
    if (sessionId) loadSession();
}

function copyText(id, btnId) {
    navigator.clipboard.writeText($(id).textContent).then(function() {
        var btn = $(btnId);
        var orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = orig; }, 2000);
    });
}

$('btn-connect').onclick = connect;
$('btn-sign').onclick = sign;
$('copy-sig').onclick = function() { copyText('sig', 'copy-sig'); };
$('reset-sign').onclick = resetSign;
$('code').onkeypress = function(e) { if (e.key === 'Enter') $('machine').focus(); };
$('machine').onkeypress = function(e) { if (e.key === 'Enter') sign(); };

// Auto-connect if wallet is already connected
if (window.ethereum && window.ethereum.selectedAddress) {
    addr = window.ethereum.selectedAddress;
    $('wallet-address').textContent = 'Connected: ' + addr;
    $('step-connect').classList.add('hidden');
    $('step-sign').classList.remove('hidden');
    if (sessionId) loadSession();
}
})();
