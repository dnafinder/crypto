function out = incompletecct(text,key,direction)
%INCOMPLETECCT Incomplete Columnar Transposition cipher encoder/decoder
% This function implements the ACA-style Incomplete Columnar Transposition.
% The plaintext (letters A–Z only) is written row-wise into a rectangle
% with a fixed number of columns equal to the key length. The last row is
% allowed to be incomplete (no padding is added). Ciphertext is obtained by
% reading column-wise according to the numeric key order.
%
% Compared with COMPLETE COLUMNAR TRANSPOSITION (CCT):
% - CCT pads the rectangle to a full grid.
% - INCOMPLETECCT keeps the last row incomplete (no padding), so some
%   columns have one fewer letter.
%
% Syntax:
%   out = incompletecct(text,key,direction)
%
% Inputs:
%   text      - Character array to encode or decode.
%   key       - Numeric row vector, a permutation of 1:M (M = number of columns).
%   direction - 1 to encrypt, -1 to decrypt.
%
% Outputs:
%   out       - Structure with fields:
%               out.plain      : Plaintext (letters only, uppercase).
%               out.key        : Used numeric key.
%               out.encrypted  : Ciphertext (letters only, uppercase).
%
% Example:
% out = incompletecct('Hide the gold into the tree stump',[3 4 1 2],1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: [3 4 1 2]
%     encrypted: 'DEDOTSPEGITRTHTONHEUIHLTEEM'
% 
% out = incompletecct('DEDOTSPEGITRTHTONHEUIHLTEEM',[3 4 1 2],-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'DEDOTSPEGITRTHTONHEUIHLTEEM'
%           key: [3 4 1 2]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%
% See also cct
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% Input parsing and validation
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},...
    {'row','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% Validate key as a permutation 1:M
M    = max(key);
skey = sort(key);
assert(isequal(skey,1:M),'This key can not be used. Check it!');
clear skey

% Normalize text: keep only A–Z
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];
ctext = char(ctext);

% Basic sizes
LT = length(ctext);      % number of letters
C  = length(key);        % number of columns

% Determine rows (R) and number of full columns (S) for incomplete grid
% If S == 0: all columns have R letters.
% If S > 0 : first S columns have R letters, remaining C-S have R-1.
if LT == 0
    R = 0;
    S = 0;
else
    if mod(LT,C) == 0
        R = LT / C;
        S = 0;
    else
        R = ceil(LT / C);
        S = LT - (R - 1) * C;
        assert(S > 0 && S < C,'Inconsistent text length for this key.');
    end
end

switch direction
    case 1  % Encrypt
        out.plain = char(ctext);
        out.key   = key;

        if LT == 0
            out.encrypted = '';
            return
        end

        % Step 1: build columns from row-wise fill (incomplete last row, no padding)
        cols = cell(1,C);
        idx  = 1;
        for r = 1:R
            for c = 1:C
                if r < R || (r == R && (S == 0 || c <= S))
                    cols{c}(end+1) = ctext(idx); 
                    idx = idx + 1;
                    if idx > LT
                        break;
                    end
                end
            end
        end

        % Step 2: read columns in key order
        [~,Idx] = sort(key);
        tmp = '';
        for k = 1:C
            tmp = [tmp cols{Idx(k)}]; %#ok<AGROW>
        end

        out.encrypted = tmp;
        clear tmp cols Idx

    case -1 % Decrypt
        out.encrypted = char(ctext);
        out.key       = key;

        if LT == 0
            out.plain = '';
            return
        end

        % Step 1: column lengths in writing order (before permutation)
        colLen = zeros(1,C);
        for c = 1:C
            if S == 0 || c <= S
                colLen(c) = R;
            else
                colLen(c) = R - 1;
            end
        end

        % Step 2: split ciphertext into columns according to key order
        [~,Idx] = sort(key);
        cols    = cell(1,C);
        pos     = 1;
        for k = 1:C
            c   = Idx(k);           % original column index
            len = colLen(c);
            if len > 0
                cols{c} = ctext(pos:pos+len-1);
                pos     = pos + len;
            else
                cols{c} = '';
            end
        end
        clear Idx colLen pos

        % Step 3: reconstruct plaintext reading row-wise (respecting incompleteness)
        pt = '';
        for r = 1:R
            for c = 1:C
                if r < R || (r == R && (S == 0 || c <= S))
                    pt = [pt cols{c}(r)]; %#ok<AGROW>
                end
            end
        end

        out.plain = pt;
        clear pt cols
end
