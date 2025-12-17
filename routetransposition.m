function out=routetransposition(text,period,direction,varargin)
% ROUTETRANSPOSITION Cipher encoder/decoder
% ROUTETRANSPOSITION implements the ACA “Route Transposition” family on a
% rectangular grid, with:
%   - a configurable write-in route (how the text is written into the grid)
%   - a configurable read-out route (how the text is read from the grid)
%
% Grid sizing:
%   - The user chooses PERIOD = number of columns.
%   - The number of rows is computed automatically as:
%         rows = ceil(L / period)
%     where L is the text length after filtering.
%   - If L is not a multiple of period, the last row is completed by padding
%     with '.' (dot) until the grid is full.
%
% Limits (ACA note):
%   - maximum 8 rows
%   - maximum 10 columns
%
% Text handling:
%   - Encryption: only letters A–Z are used; all other characters are ignored.
%   - Decryption: only A–Z and '.' are used; all other characters are ignored.
%
% Default ACA excerpt variant:
%   - WriteRoute = 'altdiag'   (alternating diagonals, start at top-left,
%                              first diagonal read bottom-to-top)
%   - ReadRoute  = 'spiralcw'  (clockwise inward spiral, start at top-left,
%                              moving right first)
%
% Supported routes (as strings):
%   'row'      : row-wise left->right, top->bottom
%   'col'      : column-wise top->bottom, left->right
%   'snakeh'   : horizontal snake (rows alternate direction)
%   'snakev'   : vertical snake (columns alternate direction)
%   'diag'     : diagonals (anti-diagonals), each read top-to-bottom
%   'altdiag'  : alternating diagonals (anti-diagonals), first bottom-to-top
%   'spiralcw' : clockwise inward spiral (start top-left, go right)
%   'spiralccw': counterclockwise inward spiral (start top-left, go down)
%
% Syntax:
%   out = routetransposition(text,period,direction)
%   out = routetransposition(text,period,direction,'WriteRoute',wr,'ReadRoute',rr)
%
% Inputs:
%   text      - character array or string scalar to encode or decode
%   period    - positive integer, number of columns (must be <= 10)
%   direction - 1 to encrypt, -1 to decrypt
%   wr        - (optional) write-in route name (default 'altdiag')
%   rr        - (optional) read-out route name (default 'spiralcw')
%
% Output (structure):
%   out.plain      - processed plaintext (A–Z only) [present after encryption; after decryption]
%   out.encrypted  - processed ciphertext (A–Z plus '.' padding) [present after encryption; before decryption]
%   out.period     - the period actually used (number of columns)
%   out.route      - struct with fields:
%                      out.route.write : write-in route name
%                      out.route.read  : read-out route name
%
% Example:
%   out = routetransposition('Hide the gold into the tree stump',7,1)
% 
% out = 
% 
%   struct with fields:
% 
%        period: 7
%         route: [1×1 struct]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'HIHETOESP.MUTEDLEDTGNTETRHIO'
%
% out = routetransposition('HIHETOESP.MUTEDLEDTGNTETRHIO',7,-1)
% 
% out = 
% 
%   struct with fields:
% 
%        period: 7
%         route: [1×1 struct]
%     encrypted: 'HIHETOESP.MUTEDLEDTGNTETRHIO'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto


writeRoute = 'altdiag';
readRoute  = 'spiralcw';
padChar    = '.';

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addParameter(p,'WriteRoute',writeRoute,@(x) ischar(x) || (isstring(x) && isscalar(x)));
addParameter(p,'ReadRoute', readRoute, @(x) ischar(x) || (isstring(x) && isscalar(x)));
parse(p,text,period,direction,varargin{:});

writeRoute = char(lower(string(p.Results.WriteRoute)));
readRoute  = char(lower(string(p.Results.ReadRoute)));
clear p

if isstring(text); text = char(text); end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

cols = period;
assert(cols>=2,'period (cols) must be >= 2.')
assert(cols<=10,'period (cols) must be <= 10 (ACA rectangle max cols = 10).')

% store indispensable metadata
out.period = cols;
out.route  = struct('write',writeRoute,'read',readRoute);

% -------------------- Preprocess text --------------------
switch direction
    case 1 % Encrypt: A-Z only
        t = double(upper(text));
        t(t<65 | t>90) = [];
        ctext = char(t);
        out.plain = ctext;

    case -1 % Decrypt: A-Z and padChar
        t = double(upper(text));
        keep = (t>=65 & t<=90) | (t==double(padChar));
        ctext = char(t(keep));
        out.encrypted = ctext;
end
clear t keep

if isempty(ctext)
    if direction == 1
        out.encrypted = '';
    else
        out.plain = '';
    end
    return
end

% -------------------- Determine rows and block size --------------------
L = numel(ctext);
rows = ceil(L/cols);
assert(rows<=8,'rows=%d exceeds ACA limit (max 8). Reduce text length or increase period.',rows);

blk = rows*cols;

% routes
pin  = routePositions(writeRoute,rows,cols); % write-in
pout = routePositions(readRoute, rows,cols); % read-out

% -------------------- Encrypt --------------------
if direction == 1
    pt = ctext;
    if numel(pt) < blk
        pt = [pt repmat(padChar,1,blk-numel(pt))];
    end

    G = repmat(padChar,rows,cols);
    for k = 1:blk
        r = pin(k,1); c = pin(k,2);
        G(r,c) = pt(k);
    end

    res = repmat(padChar,1,blk);
    for k = 1:blk
        r = pout(k,1); c = pout(k,2);
        res(k) = G(r,c);
    end

    out.encrypted = res;
    return
end

% -------------------- Decrypt --------------------
ct = ctext;
if numel(ct) < blk
    ct = [ct repmat(padChar,1,blk-numel(ct))];
end
ct = ct(1:blk); % single block

G = repmat(padChar,rows,cols);
for k = 1:blk
    r = pout(k,1); c = pout(k,2);
    G(r,c) = ct(k);
end

pt = repmat(padChar,1,blk);
for k = 1:blk
    r = pin(k,1); c = pin(k,2);
    pt(k) = G(r,c);
end

while ~isempty(pt) && pt(end)==padChar
    pt(end) = [];
end

out.plain = pt;

end

% ======================================================================
% Local functions
% ======================================================================

function P = routePositions(name,rows,cols)
switch name
    case {'row','rowwise'}
        P = posRowwise(rows,cols);
    case {'col','colwise'}
        P = posColwise(rows,cols);
    case {'snakeh','snake','hsnake'}
        P = posSnakeH(rows,cols);
    case {'snakev','vsnake'}
        P = posSnakeV(rows,cols);
    case {'diag','diagonal'}
        P = posDiag(rows,cols);
    case {'altdiag','alternatingdiagonals'}
        P = posAltDiagonals(rows,cols);
    case {'spiralcw','cwspiral'}
        P = posSpiralCW(rows,cols);
    case {'spiralccw','ccwspiral'}
        P = posSpiralCCW(rows,cols);
    otherwise
        error('Unsupported route "%s".',name);
end
end

function P = posRowwise(rows,cols)
P = zeros(rows*cols,2);
k = 1;
for r = 1:rows
    for c = 1:cols
        P(k,:) = [r c]; k = k + 1;
    end
end
end

function P = posColwise(rows,cols)
P = zeros(rows*cols,2);
k = 1;
for c = 1:cols
    for r = 1:rows
        P(k,:) = [r c]; k = k + 1;
    end
end
end

function P = posSnakeH(rows,cols)
P = zeros(rows*cols,2);
k = 1;
for r = 1:rows
    if mod(r,2)==1
        for c = 1:cols
            P(k,:) = [r c]; k = k + 1;
        end
    else
        for c = cols:-1:1
            P(k,:) = [r c]; k = k + 1;
        end
    end
end
end

function P = posSnakeV(rows,cols)
P = zeros(rows*cols,2);
k = 1;
for c = 1:cols
    if mod(c,2)==1
        for r = 1:rows
            P(k,:) = [r c]; k = k + 1;
        end
    else
        for r = rows:-1:1
            P(k,:) = [r c]; k = k + 1;
        end
    end
end
end

function P = posDiag(rows,cols)
P = zeros(rows*cols,2);
idx = 1;
for s = 0:(rows+cols-2)
    cells = zeros(min(rows,cols),2);
    m = 0;
    for r = 1:rows
        c = (s+2) - r;
        if c>=1 && c<=cols
            m = m + 1;
            cells(m,:) = [r c];
        end
    end
    cells = cells(1:m,:);
    [~,ord] = sort(cells(:,1),'ascend');
    cells = cells(ord,:);
    P(idx:idx+m-1,:) = cells;
    idx = idx + m;
end
end

function P = posAltDiagonals(rows,cols)
P = zeros(rows*cols,2);
idx = 1;
for s = 0:(rows+cols-2)
    cells = zeros(min(rows,cols),2);
    m = 0;
    for r = 1:rows
        c = (s+2) - r;
        if c>=1 && c<=cols
            m = m + 1;
            cells(m,:) = [r c];
        end
    end
    cells = cells(1:m,:);
    if mod(s,2)==0
        [~,ord] = sort(cells(:,1),'descend');
    else
        [~,ord] = sort(cells(:,1),'ascend');
    end
    cells = cells(ord,:);
    P(idx:idx+m-1,:) = cells;
    idx = idx + m;
end
end

function P = posSpiralCW(rows,cols)
P = zeros(rows*cols,2);
idx = 1;
top = 1; left = 1; bottom = rows; right = cols;
while top<=bottom && left<=right
    for c = left:right
        P(idx,:) = [top c]; idx = idx + 1;
    end
    top = top + 1;
    for r = top:bottom
        P(idx,:) = [r right]; idx = idx + 1;
    end
    right = right - 1;
    if top<=bottom
        for c = right:-1:left
            P(idx,:) = [bottom c]; idx = idx + 1;
        end
        bottom = bottom - 1;
    end
    if left<=right
        for r = bottom:-1:top
            P(idx,:) = [r left]; idx = idx + 1;
        end
        left = left + 1;
    end
end
end

function P = posSpiralCCW(rows,cols)
P = zeros(rows*cols,2);
idx = 1;
top = 1; left = 1; bottom = rows; right = cols;
while top<=bottom && left<=right
    for r = top:bottom
        P(idx,:) = [r left]; idx = idx + 1;
    end
    left = left + 1;
    for c = left:right
        P(idx,:) = [bottom c]; idx = idx + 1;
    end
    bottom = bottom - 1;
    if left<=right
        for r = bottom:-1:top
            P(idx,:) = [r right]; idx = idx + 1;
        end
        right = right - 1;
    end
    if top<=bottom
        for c = right:-1:left
            P(idx,:) = [top c]; idx = idx + 1;
        end
        top = top + 1;
    end
end
end