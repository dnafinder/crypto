⁹function out = monomedinome(text,key,digitkey,direction)
% MONOMEDINOME Cipher encoder/decoder
% MONOMEDINOME is an ACA Monome-Dinome fractionating cipher based on:
%   - a keyed 3x8 box (24 symbols) built from A–Z with two merged pairs:
%       I/J merged as I (J -> I)
%       Y/Z merged as Y (Z -> Y)
%   - a 10-digit key that defines:
%       * 2 row digits  (for rows 2 and 3)
%       * 8 column digits (for columns 1..8)
%
% Row 1 letters are encoded by a single column digit.
% Row 2 and Row 3 letters are encoded by two digits: (row digit)(column digit).
%
% This implementation preserves only A–Z (letters) from plaintext input.
% All other characters are ignored during encryption. During decryption only
% digits are used; all other characters are ignored.
%
% Syntax:
%   out = monomedinome(text,key,digitkey,direction)
%
% Input:
%   text      - character array to encode or decode
%   key       - character array used to generate the keyed 24-letter box
%               (only A–Z are used; other characters are ignored)
%   digitkey  - 10 unique digits (0-9) as char array or numeric vector
%               First 2 digits = row digits; last 8 digits = column digits
%   direction - 1 to encrypt, -1 to decrypt
%
% Output:
%   out       - structure with fields:
%                 out.plain      : plaintext (uppercase, letters only, merges applied)
%                 out.key        : cleaned key actually used (uppercase, merges applied)
%                 out.encrypted  : ciphertext digit stream (digits only)
%
% Example:
% 
% out = monomedinome('HIDE THE GOLD INTO THE TREE STUMP','LEPRACHAUN','6318927054',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: '560698325867311696061323132583228839324649'
% 
% out = monomedinome('560698325867311696061323132583228839324649','LEPRACHAUN','6318927054',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'LEPRACHAUN'
%     encrypted: '560698325867311696061323132583228839324649'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'digitkey',@(x) ischar(x) || isnumeric(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,digitkey,direction);
clear p

% -------------------- Parse digit key --------------------
if isnumeric(digitkey)
    dk = digitkey(:).';
    validateattributes(dk,{'numeric'},{'real','finite','nonnan','integer','>=',0,'<=',9});
    assert(numel(dk)==10,'digitkey must contain exactly 10 digits (0-9).');
    d = char('0' + dk);
else
    d = regexprep(digitkey,'\D','');
    assert(numel(d)==10,'digitkey must contain exactly 10 digits (0-9).');
end
assert(numel(unique(d))==10,'digitkey must contain 10 unique digits (a permutation of 0-9).');

rowdigits = d(1:2);
coldigits = d(3:10);
assert(~any(ismember(rowdigits,coldigits)),'Row digits must be distinct from column digits.');

% -------------------- Build keyed 3x8 box (24 symbols) --------------------
% Merge rules (fixed): J->I and Z->Y
% Remove J and Z from working alphabet
A = 65:90;           % 'A'..'Z'
removed = [74 90];   % 'J','Z'
A24 = A(~ismember(A,removed));

% Clean key: keep A-Z, apply merges, unique stable
ckey = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];
ckey(ckey == 74) = 73;  % J->I
ckey(ckey == 90) = 89;  % Z->Y
ckey = unique(ckey,'stable');
ckey(ckey == 74 | ckey == 90) = []; % safety

% Complete the 24-symbol keyed alphabet
A2 = A24(~ismember(A24,ckey));
keyedAlphabet = [ckey A2];

assert(numel(keyedAlphabet)==24,'Keyed alphabet must contain 24 symbols (check key/merge rules).');
assert(numel(unique(keyedAlphabet))==24,'Keyed alphabet contains duplicates (check key processing).');

% 3x8 box filled row-wise
box = reshape(char(keyedAlphabet),8,3).';

% Map letter -> index in keyedAlphabet (1..24), 0 if not present
idxMap = zeros(1,26);
for k = 1:24
    idxMap(keyedAlphabet(k)-64) = k;
end
clear k

% Digit lookups for decryption
colDigitToCol = zeros(1,10); % digit 0..9 -> col index 1..8 (0 means invalid)
for k = 1:8
    colDigitToCol(coldigits(k)-'0'+1) = k;
end
rowDigitToRow = zeros(1,10); % digit 0..9 -> row index 2/3 (0 means "not a row digit")
rowDigitToRow(rowdigits(1)-'0'+1) = 2;
rowDigitToRow(rowdigits(2)-'0'+1) = 3;
clear k

% Store cleaned key
out.key = key;

% -------------------- Preprocess text --------------------
switch direction
    case 1 % Encrypt: keep only A-Z and apply merges
        t = double(upper(text));
        t(t < 65 | t > 90) = [];
        t(t == 74) = 73; % J->I
        t(t == 90) = 89; % Z->Y
        ctext = char(t);
        out.plain = ctext;
    case -1 % Decrypt: keep only digits
        ctext = regexprep(text,'\D','');
        out.encrypted = ctext;
end

% -------------------- Common checks --------------------
if isempty(ctext)
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% -------------------- Encrypt --------------------
if direction == 1
    L = length(ctext);
    res = repmat('0',1,2*L); % worst case: 2 digits per symbol
    pos = 0;

    for k = 1:L
        ch = double(ctext(k));
        idx = idxMap(ch-64);
        assert(idx > 0,'Plaintext contains a letter not representable in the 24-symbol box.');

        row = ceil(idx/8);
        col = idx - (row-1)*8;

        if row == 1
            pos = pos + 1;
            res(pos) = coldigits(col);
        else
            pos = pos + 2;
            res(pos-1) = rowdigits(row-1); % row 2->rowdigits(1), row 3->rowdigits(2)
            res(pos)   = coldigits(col);
        end
    end

    out.encrypted = res(1:pos);
    return
end

% -------------------- Decrypt --------------------
digs = ctext;
N = length(digs);

pt = repmat('A',1,N); % upper bound
pos = 0;
i = 1;

while i <= N
    dd = digs(i)-'0'+1;
    assert(dd>=1 && dd<=10,'Ciphertext contains non-digit characters after cleaning (unexpected).');

    row = rowDigitToRow(dd);
    if row ~= 0
        i = i + 1;
        assert(i <= N,'Ciphertext ended unexpectedly after a row digit.');
        dc = digs(i)-'0'+1;
        col = colDigitToCol(dc);
        assert(col ~= 0,'Invalid column digit following a row digit.');
        pos = pos + 1;
        pt(pos) = box(row,col);
        i = i + 1;
    else
        col = colDigitToCol(dd);
        assert(col ~= 0,'Invalid column digit in ciphertext.');
        pos = pos + 1;
        pt(pos) = box(1,col);
        i = i + 1;
    end
end

out.plain = pt(1:pos);
end
