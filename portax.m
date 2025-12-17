function out=portax(text,key,direction)
% PORTAX Cipher encoder/decoder (ACA)
% PORTAX uses a two-alphabet "slide" with:
%   A1 (top): 2x13, row1 = A..M, row2 = N..Z
%   A2 (bottom): 2x13 in letter-pairs, row1 = A C E ... Y, row2 = B D F ... Z
%
% Only letters A-Z are processed; other characters are ignored.
% On decryption, trailing padding 'X' characters are removed.
%
% Syntax:
%   out = portax(text,key,direction)
%
% Input:
%   text      - character array or string scalar to encode or decode
%   key       - keyword (letters A-Z); period = length(key) after filtering
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal):
%   out.plain      - processed plaintext (A-Z only)
%   out.key        - original key as provided by user
%   out.encrypted  - processed ciphertext (A-Z only)
%
% Example:
%
% out = portax('Hide the gold into the tree stump','LEPRACHAUN',1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'JCMBUIACZCZUVZMRPMXJGJRQYKVYOSTNZDPBLVPH'
%
% out = portax('JCMBUIACZCZUVZMRPMXJGJRQYKVYOSTNZDPBLVPH','LEPRACHAUN',-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%     encrypted: 'JCMBUIACZCZUVZMRPMXJGJRQYKVYOSTNZDPBLVPH'
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

% Keep original key (black box)
out.key = key;

% -------------------- Clean key (internal) --------------------
k = double(upper(key));
k(k<65 | k>90) = [];
assert(~isempty(k),'Key must contain at least one valid letter A-Z.')
period = numel(k);

% -------------------- Clean text --------------------
t = double(upper(text));
t(t<65 | t>90) = [];
ctext = char(t);
clear t

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

% -------------------- Build rectangle (rows x period) --------------------
L = numel(ctext);
rows = ceil(L/period);
if rows < 2
    rows = 2;
end
if mod(rows,2) ~= 0
    rows = rows + 1;
end
blk = rows*period;

padChar = 'X';
if L < blk
    ctext = [ctext repmat(padChar,1,blk-L)];
end

% Fill row-wise
M = reshape(ctext(1:blk),period,rows).';
clear ctext

% -------------------- Apply PORTAX by columns, vertical pairs --------------------
% A1 (fixed): 2x13
% row 1: A..M (65..77), row 2: N..Z (78..90)
A1 = [65:77; 78:90];

for j = 1:period
    keyLetter = k(j);
    shift = keyShift(keyLetter); % 0..12, derived from A2 column of key letter

    for r = 1:2:rows
        topCh = M(r,j);
        botCh = M(r+1,j);

        [cTop,cBot] = portaxPair(topCh,botCh,A1,shift);

        M(r,j)   = cTop;
        M(r+1,j) = cBot;
    end
end

% Take off by horizontal rows
res = char(reshape(M.',1,[]));

if direction == 1
    out.encrypted = res;
else
    % remove trailing padding X (only)
    while ~isempty(res) && res(end)==padChar
        res(end) = [];
    end
    out.plain = res;
end

end

% ======================================================================
% Local functions
% ======================================================================

function shift = keyShift(keyLetter)
% A2 columns are pairs: (A,B)=1, (C,D)=2, ..., (Y,Z)=13
idx = keyLetter - 65;         % 0..25
baseCol = floor(idx/2) + 1;   % 1..13
shift = baseCol - 1;          % 0..12 (align baseCol to column 1)
end

function [rA1,cA1] = locA1(ch)
if ch <= 77 % A..M
    rA1 = 1;
    cA1 = ch - 64; % A->1
else         % N..Z
    rA1 = 2;
    cA1 = ch - 77; % N->1
end
end

function [rA2,baseCol] = locA2(ch)
idx = ch - 65;              % 0..25
baseCol = floor(idx/2) + 1; % 1..13
rA2 = mod(idx,2) + 1;       % row1 for even (A,C,...) ; row2 for odd (B,D,...)
end

function alignedCol = baseToAligned(baseCol,shift)
alignedCol = mod(baseCol - shift - 1,13) + 1; % 1..13
end

function ch = a2At(alignedCol,row,shift)
% alignedCol -> baseCol (inverse shift), then map row/col back to letter
baseCol = mod(alignedCol + shift - 1,13) + 1; % 1..13
idx = (baseCol-1)*2 + (row-1);                % 0..25
ch = idx + 65;
end

function [cTop,cBot] = portaxPair(topCh,botCh,A1,shift)
% Locate top in A1, bottom in A2 (with aligned column)
[rT,cT] = locA1(topCh);
[rB,baseColB] = locA2(botCh);
cB = baseToAligned(baseColB,shift);

if cT == cB
    % Same vertical line: take the other two letters on that line
    cTop = A1(3-rT,cT);
    cBot = a2At(cB,3-rB,shift);
else
    % Rectangle: take other two corners, top first
    cTop = A1(rT,cB);
    cBot = a2At(cT,rB,shift);
end
end
