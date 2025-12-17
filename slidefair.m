function out=slidefair(text,key,direction,table)
% SLIDEFAIR Cipher encoder/decoder
% Slidefair is a periodic digraph substitution that combines Vigenère-family
% tables with a Playfair-like rectangle rule on a 2-row tableau:
%   - first letter is located in the top alphabet (A..Z),
%   - second letter is located in the keyed row determined by the current
%     keyword letter (period = length(keyword)),
%   - the two plaintext letters are opposite corners of a rectangle; the
%     other corners are the ciphertext letters (top first).
% If the letters form a vertical pair (same column), the cipher equivalent
% is the pair just to the right (encrypt) or to the left (decrypt).
%
% Supported tables:
%   - 'vigenere' (default)
%   - 'variant'
%   - 'beaufort'
%
% Only letters A-Z are processed; other characters are ignored.
% If plaintext has odd length, a trailing 'X' is appended internally.
% On decryption, a trailing 'X' is removed (single) if present.
%
% Syntax:  out=slidefair(text,key,direction,table)
%
% Input:
%   text      - character array or string scalar to encode or decode
%   key       - keyword (character array or string scalar)
%   direction - 1 to encrypt, -1 to decrypt
%   table     - (optional) 'vigenere'|'variant'|'beaufort' (default 'vigenere')
%
% Output (minimal):
%   out.plain      : the plaintext (processed)
%   out.key        : the original key as provided by user
%   out.encrypted  : the ciphertext (processed)
%
% Example:
%
% out = slidefair('Hide the gold into the tree stump','LEPRACHAUN',1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'XSAHSIPVLOGFMUTOKBEGTPPWXJGG'
%
% out = slidefair('XSAHSIPVLOGFMUTOKBEGTPPWXJGG','LEPRACHAUN',-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%     encrypted: 'XSAHSIPVLOGFMUTOKBEGTPPWXJGG'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Default optional argument --------------------
if nargin < 4
    table = 'vigenere';
end

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'table','vigenere',@(x) ischar(x) || (isstring(x) && isscalar(x)));

parse(p,text,key,direction,table);
table = p.Results.table;
clear p

if isstring(text);  text  = char(text);  end
if isstring(key);   key   = char(key);   end
if isstring(table); table = char(table); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

out.key = key;

% -------------------- Normalize table selection --------------------
tname = lower(strtrim(table));
switch tname
    case {'v','vig','vigenere'}
        tmode = 1; % c = p + k
    case {'var','variant'}
        tmode = 2; % c = p - k
    case {'b','beau','beaufort'}
        tmode = 3; % c = k - p
    otherwise
        error('Unsupported table. Use ''vigenere'', ''variant'', or ''beaufort''.');
end

% -------------------- Filter text and key (A-Z only) --------------------
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];

ckey = double(upper(key));
ckey(ckey<65 | ckey>90) = [];
assert(~isempty(ckey),'Key must contain at least one valid letter A-Z.')

switch direction
    case 1
        assert(~isempty(ctext),'Text must contain at least one valid letter A-Z.')
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end

if isempty(ctext)
    if direction == 1
        out.encrypted = '';
    else
        out.plain = '';
    end
    return
end

% -------------------- Prepare working text --------------------
w = char(ctext);
if direction == 1
    if mod(numel(w),2) ~= 0
        w(end+1) = 'X';
    end
else
    assert(mod(numel(w),2)==0,'Ciphertext length must be even after filtering.')
end

ndig = numel(w)/2;
klen = numel(ckey);

res = repmat('A',1,2*ndig);

% -------------------- Process pairs --------------------
for i = 1:ndig
    K = double(ckey(mod(i-1,klen)+1)) - 65; % 0..25

    a = double(w(2*i-1)) - 65; % 0..25 (top)
    b = double(w(2*i))   - 65; % 0..25 (bottom symbol value)

    col1 = a + 1;

    switch tmode
        case 1 % Vigenere: bottom(col)=col+K
            col2 = mod(b - K,26) + 1;
        case 2 % Variant:  bottom(col)=col-K
            col2 = mod(b + K,26) + 1;
        case 3 % Beaufort: bottom(col)=K-col
            col2 = mod(K - b,26) + 1;
    end

    if col1 == col2
        if direction == 1
            col = col1 + 1; if col>26; col=1; end
        else
            col = col1 - 1; if col<1;  col=26; end
        end

        c1 = col - 1;
        c2 = bottomLetterIndex(col,K,tmode);
    else
        c1 = col2 - 1;
        c2 = bottomLetterIndex(col1,K,tmode);
    end

    res(2*i-1) = char(c1 + 65);
    res(2*i)   = char(c2 + 65);
end

% -------------------- Assign outputs --------------------
if direction == 1
    out.encrypted = res;
else
    tmp = res;
    if ~isempty(tmp) && tmp(end) == 'X'
        tmp(end) = [];
    end
    out.plain = tmp;
end

end

function idx = bottomLetterIndex(col,K,tmode)
c = col - 1;
switch tmode
    case 1
        idx = mod(c + K,26);
    case 2
        idx = mod(c - K,26);
    case 3
        idx = mod(K - c,26);
end
end
