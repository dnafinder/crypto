function out = phillips(text,key,mode,direction)
% PHILLIPS Cipher encoder/decoder (ACA) — Phillips and Phillips-RC
% This routine implements BOTH related ACA ciphers:
%   - Phillips (rows-only evolution)
%   - Phillips-RC (rows + columns evolution)
%
% Both are polyalphabetic substitutions based on a sequence of 8 evolving
% 5x5 Polybius squares (I/J combined). Each active square is used to encipher
% 5 letters, cycling through the 8 squares (overall period 40). 
%
% Square #1 construction:
%   - Use a keyed 25-letter alphabet (A–Z with J omitted; plaintext J merges into I)
%   - Fill a 5x5 square row-wise
%   - Reverse rows 2 and 4 (Phillips convention shown in ACA examples). 
%
% Square evolution:
%   Mode = 'phillips'  (rows-only, ACA Phillips):
%     From square #1:
%       #2..#5  obtained by moving row 1 downward one row at a time
%               (equivalently adjacent swaps: (1,2),(2,3),(3,4),(4,5)).
%       #6..#8  continue from #5 by moving the (next) row downward one row at a time
%               (adjacent swaps: (1,2),(2,3),(3,4)).
%   Mode = 'rc' (Phillips-RC, rows + columns, ACA):
%     Same row evolution as above, but at each step also move column 1 rightward
%     one column at a time (adjacent swaps on columns mirroring the row swaps). :contentReference[oaicite:2]{index=2}
%
% Substitution rule (active square):
%   Encrypt: replace each plaintext letter by the letter diagonally down-right
%            (wrap around edges).
%   Decrypt: inverse, diagonally up-left (wrap).
%
% Text handling:
%   - Only letters A–Z are processed; all other characters are ignored.
%   - J is merged into I.
%
% Syntax:
%   out = phillips(text,key,mode,direction)
%
% Inputs:
%   text      - char vector or string scalar to encode/decode
%   key       - keyword used to build square #1 (letters A–Z; J treated as I)
%   mode      - selects the variant:
%                'phillips'  : Phillips (rows-only)
%                'rc'        : Phillips-RC (rows + columns)
%              (aliases accepted: 'phillipsrc','phillips-rc')
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal + indispensable):
%   out.key        - original key as provided by user
%   out.mode       - normalized mode actually used ('phillips' or 'rc')
%   out.plain      - processed plaintext (A–Z only, uppercase, J->I) [encrypt]
%   out.encrypted  - processed ciphertext (A–Z only, uppercase, J->I) [decrypt]
%
% Examples
%
% out = phillips('Hide the gold into the tree stump','leprachaun','phillips',1)
%
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%          mode: 'phillips'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'KMSUWAGOZFEAGWZEKXEZUUXWIVI'
%
% out = phillips('KMSUWAGOZFEAGWZEKXEZUUXWIVI','leprachaun','phillips',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%          mode: 'phillips'
%     encrypted: 'KMSUWAGOZFEAGWZEKXEZUUXWIVI'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% out = phillips('Hide the gold into the tree stump','leprachaun','rc',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%          mode: 'rc'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'KMSUWADOZGRAGYZADXAVUUXWIVF'
% 
% out = phillips('KMSUWADOZGRAGYZADXAVUUXWIVF','leprachaun','rc',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'leprachaun'
%          mode: 'rc'
%     encrypted: 'KMSUWADOZGRAGYZADXAVUUXWIVF'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'mode',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,mode,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
if isstring(mode); mode = char(mode); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Normalize mode --------------------
m = lower(strtrim(mode));
if any(strcmp(m,{'rc','phillipsrc','phillips-rc'}))
    m = 'rc';
elseif strcmp(m,'phillips')
    m = 'phillips';
else
    error('Mode must be ''phillips'' or ''rc'' (aliases: ''phillipsrc'',''phillips-rc'').')
end

% -------------------- Output: black-box key + indispensable mode --------------------
out.key  = key;
out.mode = m;

% -------------------- Clean text (A-Z only, J->I) --------------------
t = double(upper(text));
t(t<65 | t>90) = [];
t(t==74) = 73; % J->I
ctext = char(t);
clear t

switch direction
    case 1
        out.plain = ctext;
    case -1
        out.encrypted = ctext;
end

if isempty(ctext)
    if direction == 1
        out.encrypted = '';
    else
        out.plain = '';
    end
    return
end

% -------------------- Build the 8 squares --------------------
if strcmp(m,'rc')
    squares = buildSquaresRC(key);
else
    squares = buildSquaresRowsOnly(key);
end

% -------------------- Transform --------------------
L = numel(ctext);
res = char(zeros(1,L));

for i = 1:L
    sqIdx = mod(floor((i-1)/5),8) + 1; % each square used for 5 letters
    PS = squares{sqIdx};

    [r,c] = find(PS==ctext(i),1);
    assert(~isempty(r),'Internal mapping error: character not found in square.');

    if direction == 1
        r2 = mod(r,5) + 1;   % down (wrap)
        c2 = mod(c,5) + 1;   % right (wrap)
    else
        r2 = mod(r-2,5) + 1; % up (wrap)
        c2 = mod(c-2,5) + 1; % left (wrap)
    end

    res(i) = PS(r2,c2);
end

if direction == 1
    out.encrypted = res;
else
    out.plain = res;
end

end

% ======================================================================
% Local builders
% ======================================================================
function PS1 = baseSquare(keyOriginal)
% Keyed 5x5 with I/J combined; rows 2 and 4 reversed (ACA Phillips family)
k = double(upper(keyOriginal));
k(k<65 | k>90) = [];
k(k==74) = 73; % J->I
assert(~isempty(k),'Key must contain at least one valid letter A-Z.');
k = unique(k,'stable');  % internal only

A = [65:73 75:90];        % A..Z without J
seq = [k A(~ismember(A,k))];

PS1 = reshape(seq,5,5).';
PS1(2,:) = fliplr(PS1(2,:));
PS1(4,:) = fliplr(PS1(4,:));
PS1 = char(PS1);
end

function squares = buildSquaresRowsOnly(keyOriginal)
% Phillips (rows-only evolution)
PS1 = baseSquare(keyOriginal);

squares = cell(1,8);
squares{1} = PS1;

cur = PS1;

% #2..#5: swap rows (1,2),(2,3),(3,4),(4,5)
for s = 1:4
    cur = swapRows(cur,s,s+1);
    squares{s+1} = cur;
end

% #6..#8: swap rows (1,2),(2,3),(3,4)
for s = 1:3
    cur = swapRows(cur,s,s+1);
    squares{5+s} = cur;
end
end

function squares = buildSquaresRC(keyOriginal)
% Phillips-RC (rows + columns evolution)
PS1 = baseSquare(keyOriginal);

squares = cell(1,8);
squares{1} = PS1;

cur = PS1;

% #2..#5: swap rows AND cols (1,2),(2,3),(3,4),(4,5)
for s = 1:4
    cur = swapRows(cur,s,s+1);
    cur = swapCols(cur,s,s+1);
    squares{s+1} = cur;
end

% #6..#8: swap rows AND cols (1,2),(2,3),(3,4)
for s = 1:3
    cur = swapRows(cur,s,s+1);
    cur = swapCols(cur,s,s+1);
    squares{5+s} = cur;
end
end

function M = swapRows(M,r1,r2)
tmp = M(r1,:);
M(r1,:) = M(r2,:);
M(r2,:) = tmp;
end

function M = swapCols(M,c1,c2)
tmp = M(:,c1);
M(:,c1) = M(:,c2);
M(:,c2) = tmp;
end
