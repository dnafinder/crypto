function out = grille(text,key,n,direction)
% GRILLE Cipher encoder/decoder (ACA Turning Grille)
% Turning Grille is a transposition cipher based on a perforated square mask
% (the "grille"). The plaintext is written through the holes into an n×n
% block in four successive orientations:
%   1) 0°   (original orientation)
%   2) 90°  clockwise rotation
%   3) 180° rotation
%   4) 270° clockwise rotation
% After the 4 writes, the ciphertext is obtained by reading the completed
% n×n block "across" (row-wise). The block MUST be complete. :contentReference[oaicite:0]{index=0}
%
% Parameters:
%   n   - grille size (n×n). This parameter is REQUIRED and must be EVEN.
%         It defines the block length n^2 and is therefore necessary for both
%         encryption (to know how many characters fill a block) and decryption
%         (to split the ciphertext into the correct blocks).
%
%   key - the grille perforations for the 0° orientation (ACA "sols").
%         This parameter is REQUIRED and uniquely defines the mask.
%         Key entries are cell positions numbered in ROW-MAJOR order:
%           1..n are row 1 (left to right),
%           n+1..2n are row 2, etc., up to n^2.
%         The key must contain exactly n^2/4 positions (the number of holes).
%         The four rotated masks must cover each of the n^2 cells EXACTLY ONCE;
%         otherwise the grille is invalid (overwrites or unfilled cells) and
%         decryption is not well-defined. 
%
% Text handling:
%   - Only letters A–Z are processed; all other characters are ignored.
%   - Encryption pads the final partial block (if any) using a fixed, highly
%     unlikely 6-letter sequence (internal default) repeated as needed.
%     Decryption removes the longest trailing suffix that matches the expected
%     padding stream; the removed length may be 1..(n^2-1) characters.
%
% Syntax:
%   out = grille(text,key,n,direction)
%
% Inputs:
%   text      - char vector or string scalar (plaintext or ciphertext)
%   key       - numeric vector, length n^2/4, positions in 1..n^2 (row-major)
%   n         - even positive integer (grille size)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal):
%   out.key        - key as provided by user (numeric vector)
%   out.plain      - processed plaintext (A–Z only, uppercase) [encrypt]
%   out.encrypted  - processed ciphertext (A–Z only, uppercase) [decrypt]
%
% Examples:
%
% out = grille('HIDE THE GOLD INTO THE TREE STUMP',[1 8 10 12],4,1)
%
% out =
%
%   struct with fields:
%
%           key: [1 8 10 12]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'HNTTOHLIDDOETEGIHJXEUEMEPTZRQSTQ'
%
% out = grille('HNTTOHLIDDOETEGIHJXEUEMEPTZRQSTQ',[1 8 10 12],4,-1)
%
% out =
%
%   struct with fields:
%
%           key: [1 8 10 12]
%     encrypted: 'HNTTOHLIDDOETEGIHJXEUEMEPTZRQSTQ'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also railfence, redefence, route
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto


% -------------------- Fixed padding (not user-configurable) --------------------
PAD = 'QJXZQK'; % 6-letter, highly unlikely sequence

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) isnumeric(x) && isvector(x) && ~isempty(x));
addRequired(p,'n',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,n,direction);
clear p

if isstring(text); text = char(text); end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')
assert(mod(n,2)==0,'n must be even.')
assert(n<=12,'n must be <= 12')

key = key(:).';
validateattributes(key,{'numeric'},{'integer','positive','finite','nonnan'})
assert(all(key>=1 & key<=n*n),'Key entries must be in 1..n^2.')
assert(numel(key)==(n*n)/4,'Key must contain exactly n^2/4 perforations.')
assert(numel(unique(key))==numel(key),'Key contains duplicate positions.')

out.key = key;

% -------------------- Build Position-1 mask from ROW-MAJOR key --------------------
mask1 = false(n,n);
for k = 1:numel(key)
    pos = key(k);
    r = floor((pos-1)/n) + 1;
    c = mod(pos-1,n) + 1;
    mask1(r,c) = true;
end

% Precompute 4 masks (clockwise rotations)
masks = cell(1,4);
masks{1} = mask1;
masks{2} = rot90(mask1,-1);
masks{3} = rot90(mask1,-2);
masks{4} = rot90(mask1,-3);

% Validate turning grille covers all cells exactly once across 4 rotations
cover = zeros(n,n);
for i = 1:4
    cover = cover + masks{i};
end
assert(all(cover(:)==1),'Invalid grille: holes do not cover each cell exactly once across 4 rotations.')
clear cover i

% Hole indices in "write in across" order (row-major) for each rotation
holeOrder = cell(1,4);
for i = 1:4
    [rr,cc] = find(masks{i});
    [~,ord] = sortrows([rr cc],[1 2]);
    rr = rr(ord); cc = cc(ord);
    holeOrder{i} = sub2ind([n n],rr,cc);
end
clear rr cc ord i

% -------------------- Clean text (A-Z only) --------------------
t = double(upper(text));
t(t<65 | t>90) = [];
t = char(t);

if isempty(t)
    if direction == 1
        out.plain = '';
        out.encrypted = '';
    else
        out.encrypted = '';
        out.plain = '';
    end
    return
end

if direction == 1
    out.plain = t;
else
    out.encrypted = t;
end

blockLen = n*n;

% -------------------- Encryption --------------------
if direction == 1
    % Pad to full blocks using PAD stream
    remL = mod(numel(t),blockLen);
    if remL ~= 0
        padLen = blockLen - remL;
        padStream = repmat(PAD,1,ceil(padLen/numel(PAD)));
        t = [t padStream(1:padLen)];
    end

    nb = numel(t)/blockLen;
    ct = char(zeros(1,numel(t)));

    pos = 1;
    q = blockLen/4;

    for b = 1:nb
        grid = repmat(char(0),n,n);

        % Fill through holes in 4 rotations (write in across order)
        for r4 = 1:4
            seg = t(pos:pos+q-1);
            pos = pos + q;

            idx = holeOrder{r4};
            grid(idx) = seg;
        end

        % Read off across (row-major)
        outBlock = reshape(grid.',1,[]); % row-major linearization
        ct((b-1)*blockLen+1:b*blockLen) = outBlock;
    end

    out.encrypted = ct;
    return
end

% -------------------- Decryption --------------------
assert(mod(numel(t),blockLen)==0,'Ciphertext length must be a multiple of n^2 (complete blocks required).')

nb = numel(t)/blockLen;
pt = char(zeros(1,numel(t)));

pos = 1;
q = blockLen/4;

for b = 1:nb
    block = t((b-1)*blockLen+1:b*blockLen);

    % Fill grid across (row-major)
    grid = reshape(block,n,n).';

    % Extract quarters through holes in rotations 1..4
    for r4 = 1:4
        idx = holeOrder{r4};
        pt(pos:pos+q-1) = grid(idx);
        pos = pos + q;
    end
end

% Remove trailing padding suffix (may be 1..blockLen-1 chars)
maxPad = min(blockLen-1,numel(pt));
padStream = repmat(PAD,1,ceil(maxPad/numel(PAD)));
padStream = padStream(1:maxPad);

cut = 0;
for L = maxPad:-1:1
    if strcmp(pt(end-L+1:end), padStream(1:L))
        cut = L;
        break
    end
end
if cut > 0
    pt(end-cut+1:end) = [];
end

out.plain = pt;

end
