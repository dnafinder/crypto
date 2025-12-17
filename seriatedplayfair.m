function out=seriatedplayfair(text,key,period,direction)
% SERIATEDPLAYFAIR Cipher encoder/decoder
% Seriated Playfair (ACA): write plaintext into two rows of width PERIOD,
% read vertical pairs (columns), encipher each pair with Playfair rules,
% then take ciphertext off horizontally (row1 then row2 per group).
%
% Alphabet: A–Z with I/J combined (J->I). Only letters A–Z are processed;
% other characters are ignored.
%
% Syntax:  out=seriatedplayfair(text,key,period,direction)
%
% Input:
%   text      - char array or string scalar to encode/decode
%   key       - keyword for Playfair square (A–Z only, J->I)
%   period    - positive integer, group width
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal):
%   out.plain     : processed plaintext
%   out.key       : original key as provided by user
%   out.encrypted : processed ciphertext
%
% Example:
%
% out = seriatedplayfair('Hide the gold into the tree stump','LEPRACHAUN',7,1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'UFMLSUAFSCFKBOWMBPMAPHTOHORW'
%
% >> out = seriatedplayfair('UFMLSUAFSCFKBOWMBPMAPHTOHORW','LEPRACHAUN',7,-1)
%
% out =
%
%   struct with fields:
%
%           key: 'LEPRACHAUN'
%     encrypted: 'UFMLSUAFSCFKBOWMBPMAPHTOHORW'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

out.key = key;

% -------------------- Filter and normalize (A-Z only, J->I) --------------------
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

ckey = double(upper(key));
ckey(ckey<65 | ckey>90) = [];
ckey(ckey==74) = 73;

assert(~isempty(ctext),'Text must contain at least one valid letter A-Z.')
assert(~isempty(ckey),'Key must contain at least one valid letter A-Z.')

L = numel(ctext);
assert(period <= L,'Period must be <= message length after filtering (%d).',L)

switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end

% -------------------- Build Playfair square (same approach as playfair.m) --------------------
ckeyu = unique(ckey,'stable');
A = [65:1:73 75:1:90]; % alphabet without J
PS = reshape([ckeyu A(~ismember(A,ckeyu))],[5,5])';
clear ckeyu A

% letter->pos lookup
rowpos = zeros(1,26);
colpos = zeros(1,26);
for r = 1:5
    for c = 1:5
        ch = double(PS(r,c));
        rowpos(ch-64) = r;
        colpos(ch-64) = c;
    end
end
rowpos(10) = rowpos(9); % J->I
colpos(10) = colpos(9);

% -------------------- Encrypt --------------------
if direction == 1
    pt = char(ctext);
    [r1,r2] = buildRows(pt,period);

    M = numel(r1);
    enc1 = repmat('A',1,M);
    enc2 = repmat('A',1,M);

    for k = 1:M
        [c1,c2] = pfPair(r1(k),r2(k),PS,rowpos,colpos,1);
        enc1(k) = c1;
        enc2(k) = c2;
    end

    ng = M/period;
    res = repmat('A',1,2*M);
    pos = 1;
    for g = 1:ng
        idx = (g-1)*period + (1:period);
        res(pos:pos+period-1) = enc1(idx); pos = pos + period;
        res(pos:pos+period-1) = enc2(idx); pos = pos + period;
    end

    out.encrypted = res;
    return
end

% -------------------- Decrypt --------------------
ct = char(ctext);
Lc = numel(ct);
blocklen = 2*period;
assert(mod(Lc,blocklen)==0,'Ciphertext length must be a multiple of 2*period after filtering.')

nb = Lc/blocklen;

dec1 = repmat('A',1,nb*period);
dec2 = repmat('A',1,nb*period);

pos = 1;
pidx = 1;
for b = 1:nb
    blk = ct(pos:pos+blocklen-1);
    pos = pos + blocklen;

    c1 = blk(1:period);
    c2 = blk(period+1:end);

    for j = 1:period
        [p1,p2] = pfPair(c1(j),c2(j),PS,rowpos,colpos,-1);
        dec1(pidx) = p1;
        dec2(pidx) = p2;
        pidx = pidx + 1;
    end
end

% read off horizontally (row1 then row2 per block)
res = repmat('A',1,2*nb*period);
pos = 1;
for b = 1:nb
    idx = (b-1)*period + (1:period);
    res(pos:pos+period-1) = dec1(idx); pos = pos + period;
    res(pos:pos+period-1) = dec2(idx); pos = pos + period;
end

% remove Playfair-style fillers (same heuristics as playfair.m), then trim trailing pad
res = cleanupFiller(res);

while ~isempty(res) && (res(end)=='X' || res(end)=='Q')
    res(end) = [];
end

out.plain = res;

end

% ======================================================================
% Local functions
% ======================================================================

function [row1,row2] = buildRows(pt,period)
% Build 2-row grid with column-wise null insertion when a column would be AA.
% Null is 'X', but use 'Q' when the column letter is 'X' to avoid 'XX'.
i = 1;
L = numel(pt);
row1 = char.empty(1,0);
row2 = char.empty(1,0);

while i <= L
    r1 = repmat('X',1,period);
    r2 = repmat('X',1,period);

    for j = 1:period
        if i <= L
            r1(j) = pt(i);
            i = i + 1;
        else
            r1(j) = 'X';
        end
    end

    for j = 1:period
        if i > L
            pad = 'X';
            if r1(j) == 'X'; pad = 'Q'; end
            r2(j) = pad;
        else
            ch = pt(i);
            if ch == r1(j)
                r2(j) = 'X';
            else
                r2(j) = ch;
                i = i + 1;
            end
        end
    end

    row1 = [row1 r1]; %#ok<AGROW>
    row2 = [row2 r2]; %#ok<AGROW>
end
end

function [x,y] = pfPair(a,b,PS,rowpos,colpos,dir)
ra = rowpos(double(a)-64); ca = colpos(double(a)-64);
rb = rowpos(double(b)-64); cb = colpos(double(b)-64);

if ra == rb
    if dir == 1
        ca2 = ca + 1; if ca2 > 5; ca2 = 1; end
        cb2 = cb + 1; if cb2 > 5; cb2 = 1; end
    else
        ca2 = ca - 1; if ca2 < 1; ca2 = 5; end
        cb2 = cb - 1; if cb2 < 1; cb2 = 5; end
    end
    x = PS(ra,ca2); y = PS(rb,cb2);
elseif ca == cb
    if dir == 1
        ra2 = ra + 1; if ra2 > 5; ra2 = 1; end
        rb2 = rb + 1; if rb2 > 5; rb2 = 1; end
    else
        ra2 = ra - 1; if ra2 < 1; ra2 = 5; end
        rb2 = rb - 1; if rb2 < 1; rb2 = 5; end
    end
    x = PS(ra2,ca); y = PS(rb2,cb);
else
    x = PS(ra,cb);
    y = PS(rb,ca);
end
end

function tmp = cleanupFiller(tmp)
% Same cleanup logic as playfair.m: remove Q when it is padding for X,
% then remove X between equal letters.
L = numel(tmp);

Q = find(tmp==81);
q = [];
if ~isempty(Q)
    for I = 1:numel(Q)
        if Q(I)==L && tmp(Q(I)-1)==88
            q = [q Q(I)]; %#ok<AGROW>
        elseif Q(I)>1 && Q(I)<L && tmp(Q(I)-1)==88 && tmp(Q(I)+1)==88
            q = [q Q(I)]; %#ok<AGROW>
        end
    end
    if ~isempty(q)
        tmp(q) = [];
        L = numel(tmp);
    end
end

X = find(tmp==88);
x = [];
if ~isempty(X)
    for I = 1:numel(X)
        if X(I)>1 && X(I)<L
            if tmp(X(I)-1)==tmp(X(I)+1)
                x = [x X(I)]; %#ok<AGROW>
            end
        end
    end
    if ~isempty(x)
        tmp(x) = [];
    end
end
end
