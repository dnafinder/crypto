function out=sequencetransposition(text,key,primer,direction)
% SEQUENCETRANSPOSITION Cipher encoder/decoder (ACA)
% Implements the ACA "Sequence Transposition" procedure:
%   1) Choose a 10-letter keyphrase and a 5-digit primer.
%   2) Extend the primer to a digit sequence SS of length L (text length):
%        SS(i) = mod( SS(i-5) + SS(i-4), 10 ) for i>5
%      (i.e., 1st+2nd gives 6th, 2nd+3rd gives 7th, etc., dropping 10s).
%   3) Convert the keyphrase into a 1–0 sequence (column labels 0..9):
%      standard alphabetical ranking with duplicates left-to-right; 10 -> 0.
%   4) Apply SS sequentially to the plaintext: each plaintext letter is
%      appended to the column whose label equals the corresponding SS digit.
%   5) Ciphertext body is obtained by reading columns left-to-right in the
%      original keyphrase order.
%   6) Output formatting: prefix the 5-digit primer; append a checksum digit
%      equal to the last SS digit; append '.'.
%
% Only letters A–Z are processed from plaintext; other characters are ignored.
% Ciphertext parsing keeps A–Z, digits 0–9, and '.'; other characters ignored.
%
% Syntax:
%   out = sequencetransposition(text,key,primer,direction)
%
% Input:
%   text      - char array or string scalar to encode/decode
%   key       - keyphrase (must contain exactly 10 letters A–Z after filtering)
%   primer    - 5 digits as char/string (e.g., '69315'). On decryption it may be
%              empty ('') if the ciphertext embeds the primer as prefix.
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal but sufficient):
%   out.key        : original key as provided by user
%   out.primer     : primer actually used (indispensable)
%   out.plain      : processed plaintext (A–Z only)
%   out.encrypted  : ciphertext (primer + body + checksum + '.')
%
% Example:
%
% out = sequencetransposition('Hide the gold into the tree stump','LEPRACHAUN','69315',1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%        primer: '69315'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: '69315HOITHEGIESUEMPDTTTTHEELNRDO1.'
%
% out = sequencetransposition('69315HOITHEGIESUEMPDTTTTHEELNRDO1.','LEPRACHAUN','69315',-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%        primer: '69315'
%     encrypted: '69315HOITHEGIESUEMPDTTTTHEELNRDO1.'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'primer',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,primer,direction);
clear p

if isstring(text);   text   = char(text);   end
if isstring(key);    key    = char(key);    end
if isstring(primer); primer = char(primer); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

out.key = key;

% -------------------- Key cleanup (internal) --------------------
ckey = double(upper(key));
ckey(ckey<65 | ckey>90) = [];
assert(numel(ckey)==10,'Key must contain exactly 10 letters A-Z after filtering.')
keyseq = keyToOneZero(char(ckey)); % 1..9 and 0, length 10

% digit->column index mapping
digit2col = zeros(1,10); % index digit+1 -> column 1..10
for c = 1:10
    digit2col(keyseq(c)+1) = c;
end
assert(all(digit2col>0),'Internal key digit mapping error.')

% -------------------- Direction-specific preprocessing --------------------
if direction == 1
    % plaintext: A-Z only
    t = double(upper(text));
    t(t<65 | t>90) = [];
    plain = char(t);
    assert(~isempty(plain),'Text must contain at least one valid letter A-Z.')
    out.plain = plain;

    % primer: 5 digits required
    ptxt = double(primer);
    ptxt(ptxt<48 | ptxt>57) = [];
    primerUsed = char(ptxt);
    assert(numel(primerUsed)==5,'Primer must contain exactly 5 digits (0-9).')

else
    % ciphertext: keep A-Z, digits, '.'
    t = double(upper(text));
    keep = (t>=65 & t<=90) | (t>=48 & t<=57) | (t==46);
    ct = char(t(keep));
    assert(~isempty(ct),'Ciphertext is empty after filtering.')

    out.encrypted = ct;

    % remove trailing '.'
    if ~isempty(ct) && ct(end)=='.'
        ct(end) = [];
    end

    % parse embedded primer if present
    embeddedPrimer = '';
    if numel(ct) >= 5 && all(ct(1:5)>='0' & ct(1:5)<='9')
        embeddedPrimer = ct(1:5);
        ct(1:5) = [];
    end

    % primer argument may be empty, else must be 5 digits
    ptxt = double(primer);
    ptxt(ptxt<48 | ptxt>57) = [];
    primerArg = char(ptxt);

    if ~isempty(primerArg)
        assert(numel(primerArg)==5,'Primer must contain exactly 5 digits (0-9) if provided.')
        if ~isempty(embeddedPrimer)
            assert(strcmp(embeddedPrimer,primerArg),'Embedded primer in ciphertext does not match the provided primer.')
        end
        primerUsed = primerArg;
    else
        assert(~isempty(embeddedPrimer),'Primer not provided and not embedded in ciphertext.')
        primerUsed = embeddedPrimer;
    end

    % checksum digit (optional but expected by ACA format)
    checksum = [];
    if ~isempty(ct) && ct(end)>='0' && ct(end)<='9'
        checksum = double(ct(end)) - 48;
        ct(end) = [];
    end

    % remaining letters are ciphertext body
    body = ct(ct>='A' & ct<='Z');
    assert(~isempty(body),'Ciphertext body has no letters after parsing.')
end

out.primer = primerUsed;

% -------------------- Build sequence digits SS --------------------
if direction == 1
    L = numel(out.plain);
else
    L = numel(body);
end
SS = extendPrimer(primerUsed,L);

% checksum handling
if direction == -1 && ~isempty(checksum)
    assert(SS(end)==checksum,'Checksum mismatch (expected %d, got %d).',SS(end),checksum)
end

% -------------------- Encrypt --------------------
if direction == 1
    cols = cell(1,10);
    for i = 1:10
        cols{i} = '';
    end

    pt = out.plain;
    for i = 1:L
        d = SS(i);           % 0..9
        c = digit2col(d+1);  % 1..10
        cols{c}(end+1) = pt(i); 
    end

    bodyOut = '';
    for c = 1:10
        bodyOut = [bodyOut cols{c}]; %#ok<AGROW>
    end

    checkDigit = char(SS(end) + 48);
    out.encrypted = [primerUsed bodyOut checkDigit '.'];
    return
end

% -------------------- Decrypt --------------------
% Count how many letters belong to each digit bucket
counts = zeros(1,10);
for i = 1:L
    counts(SS(i)+1) = counts(SS(i)+1) + 1;
end

% Split ciphertext body into 10 columns in key order
colData = cell(1,10);
pos = 1;
for c = 1:10
    d = keyseq(c);
    n = counts(d+1);
    if n==0
        colData{c} = '';
    else
        colData{c} = body(pos:pos+n-1);
        pos = pos + n;
    end
end
assert(pos-1 == numel(body),'Ciphertext body length does not match expected counts.')

% Reconstruct plaintext by consuming from columns following SS
ptr = ones(1,10);
pt = repmat('A',1,L);
for i = 1:L
    d = SS(i);
    c = digit2col(d+1);
    pt(i) = colData{c}(ptr(c));
    ptr(c) = ptr(c) + 1;
end

out.plain = pt;

end

% ======================================================================
% Local functions
% ======================================================================

function keyseq = keyToOneZero(key10)
% Standard columnar ranking: alphabetical, duplicates left-to-right.
% Assign 1..10, represent 10 as 0.
letters = double(key10(:)');
idx = 1:10;
[~,ord] = sortrows([letters(:) idx(:)],[1 2]);
keyseq = zeros(1,10);
for r = 1:10
    col = ord(r);
    v = r;
    if v==10
        v = 0;
    end
    keyseq(col) = v;
end
end

function SS = extendPrimer(primer5,L)
d = double(primer5) - 48;
SS = zeros(1,L);

m = min(5,L);
SS(1:m) = d(1:m);

for i = 6:L
    SS(i) = mod(SS(i-5) + SS(i-4),10);
end
end
