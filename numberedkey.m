function out = numberedkey(text,key,offset,direction)
% NUMBEREDKEY Cipher encoder/decoder (ACA)
% This is a substitution cipher based on a "numbered extended key". :contentReference[oaicite:1]{index=1}
%
% Construction (ACA):
%   1) Start with a key word/phrase (keep letters A–Z only; duplicates are kept).
%   2) Extend it by appending any missing letters (A–Z) in alphabetical order.
%   3) Optionally "shift" (rotate) the extended key by choosing a starting
%      position (OFFSET).
%   4) Number the shifted extended key from 00 to N-1 (N = length of extended key).
%   5) Encrypt each plaintext letter by one of the numbers assigned to that
%      letter (if duplicates exist, a letter can map to multiple numbers). :contentReference[oaicite:2]{index=2}
%
% This implementation processes only letters A–Z from the input TEXT.
% For encryption, ciphertext is returned as a digit string with fixed-width
% codes (at least 2 digits, with leading zeros). For decryption, all non-digit
% characters are ignored and the digit stream is parsed in fixed-width chunks.
%
% Syntax:
%   out = numberedkey(text,key,direction)          % OFFSET defaults to 1
%   out = numberedkey(text,key,offset,direction)   % OFFSET is 1..N
%
% Inputs:
%   text      - char array or string scalar (plaintext or ciphertext)
%   key       - key word/phrase (A–Z used; duplicates kept)
%   offset    - (optional) starting position in the extended key (default 1)
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal):
%   out.key        - the original key as provided by user
%   out.plain      - plaintext (uppercase, A–Z only)
%   out.encrypted  - ciphertext (digits only, fixed-width codes)
%
% Example:
%
% out = numberedkey('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%          key: 'leprachaun'
%        plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%    encrypted: '061411012106011318001114092118210601210301012021081702'
%
% out = numberedkey('061411012106011318001114092118210601210301012021081702','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%          key: 'leprachaun'
%    encrypted: '061411012106011318001114092118210601210301012021081702'
%        plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Optional offset handling --------------------
if nargin == 3
    direction = offset;
    offset = 1;
end

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'offset',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,offset,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Output: original key --------------------
out.key = key;

% -------------------- Build extended key (A-Z only; duplicates kept) --------------------
k = upper(key);
k = k(k>='A' & k<='Z');
assert(~isempty(k),'Key must contain at least one letter A-Z.')

A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
missing = A(~ismember(A,k));          % missing letters (unique) not in the base key
extended = [k missing];              % duplicates in k are preserved

N = numel(extended);
offset = mod(offset-1,N) + 1;         % 1..N

shifted = [extended(offset:end) extended(1:offset-1)]; % shifted extended key

% Fixed-width numeric codes (ACA uses 2 digits in the example; keep >=2)
w = max(2,numel(num2str(N-1)));

% -------------------- Encryption --------------------
if direction == 1
    t = upper(text);
    t(t<'A' | t>'Z') = [];
    plain = t;

    if isempty(plain)
        out.plain = '';
        out.encrypted = '';
        return
    end

    out.plain = plain;

    % letter -> list of indices (0..N-1) in shifted key (homophonic if duplicates)
    occ = cell(1,26);
    for i = 1:N
        occ{double(shifted(i))-64}(end+1) = i-1; 
    end

    ptr = ones(1,26); % position pointer for cycling occurrences

    ct = repmat('0',1,w*numel(plain));
    pos = 1;

    for i = 1:numel(plain)
        idxList = occ{double(plain(i))-64};
        j = ptr(double(plain(i))-64);
        num = idxList(j);

        j = j + 1;
        if j > numel(idxList), j = 1; end
        ptr(double(plain(i))-64) = j;

        ct(pos:pos+w-1) = sprintf(['%0' num2str(w) 'd'],num);
        pos = pos + w;
    end

    out.encrypted = ct;
    return
end

% -------------------- Decryption --------------------
digitsOnly = text(text>='0' & text<='9');

if isempty(digitsOnly)
    out.encrypted = '';
    out.plain = '';
    return
end

assert(mod(numel(digitsOnly),w)==0, ...
    'Ciphertext digit count (%d) is not divisible by code width (%d).', numel(digitsOnly), w);

out.encrypted = digitsOnly;

M = numel(digitsOnly)/w;
pt = repmat('A',1,M);

pos = 1;
for i = 1:M
    num = str2double(digitsOnly(pos:pos+w-1));
    assert(num>=0 && num<N,'Invalid code %d (must be in 0..%d).',num,N-1)
    pt(i) = shifted(num+1);
    pos = pos + w;
end

out.plain = pt;

end
