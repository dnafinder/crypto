function out = homophonic(text,key,direction)
% HOMOPHONIC Cipher encoder/decoder (ACA-style)
% - Plain alphabet A-Z with I/J combined (J -> I)
% - 4-row numeric table with 25 columns (A..I,K..Z)
% - A 4-letter keyword (derived from KEY) sets the start position of each row
% - Each letter has 4 homophones (one per row); encryption cycles deterministically
%
% Only letters A-Z are processed; other characters are ignored.
% Ciphertext is returned as 2-digit pairs separated by single spaces.
% Decryption ignores non-digits and parses 2-digit pairs.
%
% Syntax:
%   out = homophonic(text,key,direction)
%
% Inputs:
%   text      - char vector or string scalar
%   key       - keyword (A-Z; J treated as I internally)
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal):
%   out.key        - original key as provided by user
%   out.plain      - processed plaintext (A-Z only, uppercase, J->I) [encrypt]
%   out.encrypted  - ciphertext pairs (e.g., '23 04 00 ...') [decrypt: normalized digits]
%
% Example:
% out = homophonic('Hide the gold into the tree stump','leprachaun',1)
% out =
%   struct with fields:
%          key: 'leprachaun'
%        plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%    encrypted: '23 24 19 20 09 29 26 22 04 01 50 30 03 40 35 55 69 66 78 07 89 20 08 09 10 02 05'
%
% out = homophonic('23 24 19 20 09 29 26 22 04 01 50 30 03 40 35 55 69 66 78 07 89 20 08 09 10 02 05','leprachaun',-1)
% out =
%   struct with fields:
%          key: 'leprachaun'
%    encrypted: '23 24 19 20 09 29 26 22 04 01 50 30 03 40 35 55 69 66 78 07 89 20 08 09 10 02 05'
%        plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

out.key = key;

% -------------------- Column alphabet (I/J combined) --------------------
colAlpha = ['A':'I' 'K':'Z']; % 25 letters

% -------------------- Derive 4-letter keyword from KEY --------------------
k = double(upper(key));
k(k<65 | k>90) = [];
k(k==74) = 73;              % J->I
k = unique(k,'stable');      % internal only
assert(numel(k) >= 4,'Key must provide at least 4 distinct letters A-Z (J counts as I).')
kw = char(k(1:4));

% Keyword column indices (1..25)
kwCol = zeros(1,4);
for i = 1:4
    idx = find(colAlpha == kw(i),1);
    assert(~isempty(idx),'Keyword letter %s is not valid (J not allowed; use I).',kw(i))
    kwCol(i) = idx;
end

% -------------------- Build numeric table T (4 x 25) --------------------
row1 = 1:25;
row2 = 26:50;
row3 = 51:75;
row4 = [76:99 0]; % 00 represented as 0 internally
rows = {row1,row2,row3,row4};

T = zeros(4,25);
for r = 1:4
    seq = rows{r};
    s = kwCol(r);
    % rotate right by (s-1) so seq(1) lands under column s
    krot = s - 1;
    if krot > 0
        seq = [seq(end-krot+1:end) seq(1:end-krot)];
    end
    T(r,:) = seq;
end
clear rows row1 row2 row3 row4 r i idx seq s krot

% Reverse map number -> letter (0..99)
rev = repmat('?',1,100); % index num+1
for c = 1:25
    for r = 1:4
        num = T(r,c);
        rev(num+1) = colAlpha(c);
    end
end

% -------------------- Encrypt --------------------
if direction == 1
    t = double(upper(text));
    t(t<65 | t>90) = [];
    t(t==74) = 73; % J->I
    plain = char(t);
    out.plain = plain;

    if isempty(plain)
        out.encrypted = '';
        return
    end

    % Deterministic cycling over the 4 homophones per letter
    ptr = ones(1,25); % 1..4 per column
    nums = zeros(1,numel(plain));

    for i = 1:numel(plain)
        col = find(colAlpha == plain(i),1);
        if isempty(col)
            error('Internal mapping error for letter %s.',plain(i))
        end
        r = ptr(col);
        nums(i) = T(r,col);
        r = r + 1; if r > 4, r = 1; end
        ptr(col) = r;
    end

    % Format as 'NN NN ...' (00 for zero)
    toks = cell(1,numel(nums));
    for i = 1:numel(nums)
        if nums(i) == 0
            toks{i} = '00';
        else
            toks{i} = sprintf('%02d',nums(i));
        end
    end
    out.encrypted = strjoin(toks,' ');
    return
end

% -------------------- Decrypt --------------------
% Normalize ciphertext: keep digits and spaces only (for display)
tt = upper(text);
keep = (tt>='0' & tt<='9') | isspace(tt);
tt = tt(keep);
tt = strtrim(regexprep(tt,'\s+',' '));
out.encrypted = tt;

digitsOnly = text(text>='0' & text<='9');
assert(mod(numel(digitsOnly),2)==0,'Ciphertext must contain an even number of digits (2-digit pairs).')

M = numel(digitsOnly)/2;
pt = repmat('A',1,M);

pos = 1;
for i = 1:M
    pair = digitsOnly(pos:pos+1);
    num = str2double(pair); % '00' -> 0
    assert(~isnan(num) && num>=0 && num<=99,'Invalid pair "%s".',pair)
    ch = rev(num+1);
    assert(ch~='?','Pair "%s" is not mapped by the current table.',pair)
    pt(i) = ch;
    pos = pos + 2;
end

out.plain = pt;

end
