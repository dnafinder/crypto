function out=variant(text,key,direction)
% VARIANT Cipher encoder/decoder (ACA)
% VARIANT (as per ACA excerpt) is the "Variant" Vigenere-family tableau
% where encryption is defined by:
%   C = P - K (mod 26)
% and decryption by:
%   P = C + K (mod 26)
% The plaintext is conceptually written under the keyword by columns, but
% the resulting operation is equivalent to repeating the key over the text
% stream and applying the modular subtraction/addition. :contentReference[oaicite:1]{index=1}
%
% Only letters A-Z are processed; other characters are ignored.
%
% Syntax:
%   out = variant(text,key,direction)
%
% Input:
%   text      - character array or string scalar to encode or decode
%   key       - keyword (character array or string scalar)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal):
%   out.plain     : processed plaintext (A-Z only)
%   out.key       : original key as provided by user
%   out.encrypted : processed ciphertext (A-Z only)
%
% Example:
%
% out = variant('Hide the gold into the tree stump','LEPRACHAUN',1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'WEONTFXGUYSEYCORAEZETADCUKI'
%
% out = variant('WEONTFXGUYSEYCORAEZETADCUKI','LEPRACHAUN',-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%     encrypted: 'WEONTFXGUYSEYCORAEZETADCUKI'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% Keep original key (black-box behavior)
out.key = key;

% -------------------- Filter key (A-Z only, internal) --------------------
k = double(upper(key));
k(k<65 | k>90) = [];
assert(~isempty(k),'Key must contain at least one valid letter A-Z.')

% -------------------- Filter text --------------------
t = double(upper(text));
t(t<65 | t>90) = [];
ctext = char(t);

if isempty(ctext)
    if direction == 1
        out.plain = '';
        out.encrypted = '';
    else
        out.encrypted = '';
        out.plain = '';
    end
    return
end

switch direction
    case 1
        out.plain = ctext;
    case -1
        out.encrypted = ctext;
end

% -------------------- Build keystream --------------------
L = numel(ctext);
klen = numel(k);
ks = repmat(k,1,ceil(L/klen));
ks = ks(1:L);

A = 65;
pIdx = double(ctext) - A;
kIdx = double(ks)    - A;

% -------------------- Transform --------------------
if direction == 1
    cIdx = mod(pIdx - kIdx,26);
    out.encrypted = char(cIdx + A);
else
    pIdx = mod(pIdx + kIdx,26);
    out.plain = char(pIdx + A);
end

end