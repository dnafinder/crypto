function out=headlines(text,key1,key2,key3,direction)
% HEADLINES Cipher encoder/decoder (ACA)
% The HEADLINES cipher encrypts using simple substitution on a mixed alphabet
% at varying settings "against itself", as with a K3 key. :contentReference[oaicite:1]{index=1}
%
% Mixed alphabet construction:
%   1) Build a keyword alphabet (26 letters) from KEY2 (unique letters, then
%      remaining A–Z).
%   2) Write that alphabet into a transposition block with NCOLS = length(KEY1).
%   3) Number the columns by alphabetizing KEY1 (stable for repeats, left-to-right).
%   4) Read columns DOWN in numeric order (1..NCOLS) to obtain the mixed alphabet. :contentReference[oaicite:2]{index=2}
%
% Settings:
%   KEY3 determines the running setting (period = length(KEY3 after filtering).
%   Each setting letter selects a tableau row, equivalent to a shift equal to its
%   position in the mixed alphabet. :contentReference[oaicite:3]{index=3}
%
% Only letters A–Z are processed; all other characters are ignored.
%
% Syntax:
%   out = headlines(text,key1,key2,key3,direction)
%
% Inputs:
%   text      - char array or string scalar
%   key1      - HAT keyword (determines transposition column order/width)
%   key2      - KEY keyword (builds the keyword alphabet written into the block)
%   key3      - SETTING keyword (drives the per-letter setting)
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal + indispensable):
%   out.key1      - original key1 as provided
%   out.key2      - original key2 as provided
%   out.key3      - original key3 as provided
%   out.plain     - processed plaintext (A–Z only, uppercase)
%   out.encrypted - processed ciphertext (A–Z only, uppercase)
%
% Example:
% out = headlines('Hide the gold into the tree stump','LEPRACHAUN','GOBLIN','GHOST',1)
% 
% out = 
% 
%   struct with fields:
% 
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLIN'
%          key3: 'GHOST'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'KHPUOKSLZQAHGESRBDELCSZEPFU'
% 
% out = headlines('KHPUOKSLZQAHGESRBDELCSZEPFU','LEPRACHAUN','GOBLIN','GHOST',-1)
% 
% out = 
% 
%   struct with fields:
% 
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLIN'
%          key3: 'GHOST'
%     encrypted: 'KHPUOKSLZQAHGESRBDELCSZEPFU'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key3',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,key3,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key1); key1 = char(key1); end
if isstring(key2); key2 = char(key2); end
if isstring(key3); key3 = char(key3); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Outputs: original keys --------------------
out.key1 = key1;
out.key2 = key2;
out.key3 = key3;

% -------------------- Clean text (A-Z only) --------------------
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext = char(ctext);

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

% -------------------- Clean keys (A-Z only) --------------------
hat = double(upper(key1));
hat(hat<65 | hat>90) = [];
hat = char(hat);

k2 = double(upper(key2));
k2(k2<65 | k2>90) = [];
k2 = char(k2);

setk = double(upper(key3));
setk(setk<65 | setk>90) = [];
setk = char(setk);

assert(~isempty(hat),'key1 (HAT) must contain at least one letter A-Z.')
assert(~isempty(k2),'key2 (KEY) must contain at least one letter A-Z.')
assert(~isempty(setk),'key3 (SETTING) must contain at least one letter A-Z.')

% -------------------- Build keyword alphabet from KEY2 --------------------
A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
k2u = unique(k2,'stable');
keyAlphabet = [k2u A(~ismember(A,k2u))]; % 1x26

% -------------------- Column numbering from HAT (stable for repeats) --------------------
ncols = numel(hat);
[~,sortIdx] = sortrows([hat(:) (1:ncols).'],[1 2]); 
colNum = zeros(1,ncols);
for r = 1:ncols
    colNum(sortIdx(r)) = r;
end
clear sortIdx r

% -------------------- Fill transposition block row-wise --------------------
nrows = ceil(26/ncols);
blk = repmat(char(0),nrows,ncols);
pos = 1;
for r = 1:nrows
    for c = 1:ncols
        if pos <= 26
            blk(r,c) = keyAlphabet(pos);
            pos = pos + 1;
        else
            blk(r,c) = char(0);
        end
    end
end
clear pos r c

% -------------------- Read columns DOWN in order 1..NCOLS to get mixed alphabet --------------------
mixed = repmat('A',1,26);
p2 = 1;
for k = 1:ncols
    c = find(colNum==k,1);
    col = blk(:,c);
    col(col==char(0)) = [];
    mixed(p2:p2+numel(col)-1) = col(:).';
    p2 = p2 + numel(col);
end
clear blk colNum p2 k c col

assert(numel(unique(mixed))==26,'Internal error: mixed alphabet must be a permutation of A-Z.')

% -------------------- Build ShiftStream from SETTING (repeat to length) --------------------
L  = numel(ctext);
LS = numel(setk);

% map letter -> position 0..25 in mixed alphabet
posMixed = zeros(1,26);
for i = 1:26
    posMixed(double(mixed(i))-65+1) = i-1;
end

shiftStream = zeros(1,L);
for i = 1:L
    s = setk(mod(i-1,LS)+1);
    shiftStream(i) = posMixed(double(s)-65+1);
end
clear i L LS s posMixed

% -------------------- Delegate to vigenere (extended path) --------------------
tmp = vigenere(ctext,key2,direction, ...
    'Mode','add', ...
    'PlainAlphabet',mixed, ...
    'CipherAlphabet',mixed, ...
    'ShiftStream',shiftStream);

if direction == 1
    out.encrypted = tmp.encrypted;
else
    out.plain = tmp.plain;
end

end
