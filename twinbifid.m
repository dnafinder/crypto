function out=twinbifid(text,key,period1,period2,direction)
% TWINBIFID Cipher encoder/decoder
% Twin Bifid is obtained by applying BIFID twice with the same Polybius
% square (same key) but with two (possibly different) periods.
%
% This implementation delegates all core work to bifid.m:
%   Encrypt:  C = BIFID(BIFID(P, key, period1), key, period2)
%   Decrypt:  P = BIFID(BIFID(C, key, period2, -1), key, period1, -1)
%
% English, 26 letters, alphabet is used with I/J combined (J->I).
% Only letters A-Z are processed; other characters are ignored.
%
% Syntax:  out=twinbifid(text,key,period1,period2,direction)
%
% Input:
%   text      - character array or string scalar to encode or decode
%   key       - keyword used to generate the Polybius Square
%   period1   - first bifid period (positive integer, <= message length)
%   period2   - second bifid period (positive integer, <= message length)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output:
%   out - structure with fields:
%         out.plain     : plaintext (processed)
%         out.key       : used key (processed, stable unique)
%         out.encrypted : ciphertext (processed)
%
% Example:
%
% out = twinbifid('Hide the gold into the tree stump','leprachaun',7,5,1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'HKRPDCGVONYHMLWZRMEBIYOSRID'
%
% >> out = twinbifid('HKRPDCGVONYHMLWZRMEBIYOSRID','leprachaun',7,5,-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHUN'
%     encrypted: 'HKRPDCGVONYHMLWZRMEBIYOSRID'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period1',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'period2',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period1,period2,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% -------------------- Filter and normalize (for checks + out.key) --------------------
% Filter text (A-Z only, J->I) just to validate periods and emptiness
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

% Filter key (A-Z only, J->I), then stable unique (key actually used)
ckey_raw = double(upper(key));
ckey_raw(ckey_raw>90 | ckey_raw<65) = [];
ckey_raw(ckey_raw==74) = 73;

assert(~isempty(ctext),'Text must contain at least one valid letter A-Z.')
assert(~isempty(ckey_raw),'Key must contain at least one valid letter A-Z.')

L = numel(ctext);
assert(period1 <= L,'Period1 must be <= message length after filtering (%d).',L)
assert(period2 <= L,'Period2 must be <= message length after filtering (%d).',L)

out.key = char(unique(ckey_raw,'stable'));

% -------------------- Delegate to bifid.m --------------------
switch direction
    case 1  % Encrypt: BIFID twice
        a = bifid(text,key,period1,1);
        b = bifid(a.encrypted,key,period2,1);

        out.plain = a.plain;
        out.encrypted = b.encrypted;

    case -1 % Decrypt: inverse order
        a = bifid(text,key,period2,-1);
        b = bifid(a.plain,key,period1,-1);

        out.encrypted = a.encrypted;
        out.plain = b.plain;
end

end
