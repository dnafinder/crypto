function out=myszkowski(text,key,direction)
% MYSZKOWSKI Transposition cipher encoder/decoder
% The Myszkowski transposition cipher is a variant of the columnar
% transposition that allows repeated letters in the keyword. Columns
% corresponding to the same key letter are read in a grouped row-wise
% fashion, which differentiates it from the classical columnar method
% (where all columns are distinct).
%
% Construction (ACA-style):
% 1) Choose a keyword that may contain repeated letters (e.g. MAMMAL).
% 2) Assign column numbers by ordering the distinct letters alphabetically;
%    equal letters receive the same number. For example:
%       Key:      M   A   M   M   A   L
%       Letters:  A   L   M           (sorted)
%       Numbers:  3   1   3   3   1   2  →  [3 1 3 3 1 2]
% 3) Write the (cleaned) plaintext row-wise in a rectangle having as many
%    columns as the key length.
% 4) Ciphertext is obtained by scanning the rectangle BY ROWS, first taking
%    all letters under key-number 1, then all letters under key-number 2,
%    and so on, preserving the internal row-wise order within each group.
%
% Decryption reverses this procedure by:
% 1) Reconstructing the same rectangle shape.
% 2) Filling its cells in the exact reading order used for encryption
%    (grouped by key-number, row-wise within each group) using the
%    ciphertext.
% 3) Reading the rectangle row-wise to recover the plaintext.
%
% Only letters A–Z are processed; all other characters are ignored in the
% transformation. Plaintext and ciphertext are treated as contiguous
% uppercase sequences internally.
%
% Syntax:  out = myszkowski(text,key,direction)
%
%     Input:
%         text      - Character array to encode or decode.
%         key       - Keyword (letters only are used; others are discarded).
%         direction - 1 to encrypt, -1 to decrypt.
%
%     Output (struct):
%         out.plain      - Plaintext (cleaned, A–Z only, uppercase).
%         out.key        - Cleaned keyword actually used (uppercase).
%         out.encrypted  - Ciphertext (A–Z only, uppercase).
%
% Example:
%   out = myszkowski('Hide the gold into the tree stump','leprachaun',1)
%
%   out =
%
%     struct with fields:
%
%          plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%            key: 'LEPRACHAUN'
%      encrypted: 'TGOEUHTMIIEEHPHDELRDNSETTOT'
%
%   out = myszkowski('TGOEUHTMIIEEHPHDELRDNSETTOT','leprachaun',-1)
%
%   out =
%
%     struct with fields:
%
%      encrypted: 'TGOEUHTMIIEEHPHDELRDNSETTOT'
%            key: 'LEPRACHAUN'
%          plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also cct, nicodemus, swagman, railfence
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% ------------------------ Input parsing & cleaning ------------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) ...
    validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% Clean text: keep only A–Z
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext = char(ctext);

% Clean key: keep only A–Z
ckey = double(upper(key));
ckey(ckey<65 | ckey>90) = [];
assert(~isempty(ckey),'Key must contain at least one alphabetic character.');
key_clean = char(ckey);

switch direction
    case 1 % encrypt
        out.plain = ctext;
    case -1 % decrypt
        out.encrypted = ctext;
end
out.key = key_clean;

% If there is nothing to process, return immediately
L = length(ctext);
if L==0
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% ------------------------ Numeric key (Myszkowski) -----------------------
% Map key letters to numbers: A..Z in sorted order; equal letters share
% the same number.
uk = unique(ckey,'sorted');       % distinct letters, alphabetically
numkey = zeros(size(ckey));
for i = 1:numel(uk)
    numkey(ckey==uk(i)) = i;
end
clear uk i

n = numel(numkey);               % number of columns
r = ceil(L/n);                   % number of rows

% ------------------------ Rectangle layout -------------------------------
% Matrix of characters; mask to mark used cells (last row may be incomplete)
mat  = repmat(' ',r,n);
mask = false(r,n);
idx_plain = zeros(1,L);

row = 1; col = 1;
for kpos = 1:L
    mat(row,col)    = ctext(kpos);
    mask(row,col)   = true;
    idx_plain(kpos) = sub2ind([r n],row,col);
    col = col + 1;
    if col>n
        col = 1;
        row = row + 1;
    end
end

vals = unique(numkey,'sorted');  % distinct key-numbers in ascending order

% ------------------------ Encrypt / Decrypt core -------------------------
switch direction
    case 1  % Encrypt
        tmp = repmat(' ',1,L);
        pos = 1;
        for v = vals
            cols = find(numkey==v);
            for rr = 1:r
                for cc = 1:numel(cols)
                    c = cols(cc);
                    if mask(rr,c)
                        tmp(pos) = mat(rr,c);
                        pos = pos + 1;
                    end
                end
            end
        end
        out.encrypted = tmp;
        
    case -1 % Decrypt
        tmpmat = repmat(' ',r,n);
        pos = 1;
        for v = vals
            cols = find(numkey==v);
            for rr = 1:r
                for cc = 1:numel(cols)
                    c = cols(cc);
                    if mask(rr,c)
                        tmpmat(rr,c) = ctext(pos);
                        pos = pos + 1;
                    end
                end
            end
        end
        % Recover plaintext in original row-wise fill order
        plainchars = tmpmat(idx_plain);
        out.plain = plainchars;
end
