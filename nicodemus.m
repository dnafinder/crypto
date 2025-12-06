function out = nicodemus(text, key, direction)
%NICODEMUS Cipher encoder/decoder
% The Nicodemus cipher combines:
%   1) Columnar transposition driven by a keyword.
%   2) Vigenere encipherment with the same key.
%   3) Ciphertext extraction by taking up to 5 rows at a time and reading
%      column-by-column within each block, removing spaces.
%
% This implementation follows the project variant:
% - Only A-Z letters are processed for both text and key.
% - The grid has KL columns (KL = key length).
% - Plaintext letters are written row-wise; only the last row may be padded
%   with spaces.
% - Columns are permuted according to the alphabetical order of the key.
% - Vigenere is applied row-wise using the sorted key.
% - The Vigenere output is left-justified within each row, as in the
%   original implementation style.
% - Ciphertext is produced by reading blocks of up to 5 rows, column-by-
%   column, removing spaces.
%
% Decryption reconstructs the post-Vigenere grid by filling cells in the
% same extraction order using the left-justified rule. Then it applies
% Vigenere -1 row-wise with the sorted key. For the last row only, it
% restores the original post-transposition letter positions (based on the
% key order and the last-row length) before reversing the columnar
% transposition.
%
% Dependency:
%   Requires vigenere.m available in the same repository.
%
% Syntax:
%   out = nicodemus(text, key, direction)
%
% Input:
%   text      - Character array or string scalar.
%   key       - Keyword as character array or string scalar.
%   direction -  1 to encrypt
%               -1 to decrypt
%
% Output:
%   out - A structure with fields:
%       out.plain
%       out.key
%       out.encrypted
%
% Examples:
%   out = nicodemus('Hide the gold into the tree stump','leprachaun',1)
%
%   out =
%
%     struct with fields:
%
%           plain: 'Hide the gold into the tree stump'
%             key: 'LEPRACHAUN'
%       encrypted: 'TOUGEMJVGMMTLOLSODYEGSCVKIN'
%
%   out = nicodemus('TOUGEMJVGMMTLOLSODYEGSCVKIN','leprachaun',-1)
%
%   out =
%
%     struct with fields:
%
%       encrypted: 'TOUGEMJVGMMTLOLSODYEGSCVKIN'
%             key: 'LEPRACHAUN'
%           plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% Created by Giuseppe Cardillo
% giuseppe.cardillo.75@gmail.com

% ---- Input normalization ----
if isstring(text), text = char(text); end
if isstring(key),  key  = char(key);  end

p = inputParser;
p.FunctionName = mfilename;
addRequired(p, 'text', @(x) ischar(x));
addRequired(p, 'key',  @(x) ischar(x));
addRequired(p, 'direction', @(x) validateattributes(x, {'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p, text, key, direction);

% ---- Clean text and key to A-Z ----
ctext = upper(text);
ctext = ctext(ctext >= 'A' & ctext <= 'Z');
TL = numel(ctext);

keyU = upper(key);
keyU = keyU(keyU >= 'A' & keyU <= 'Z');
KL = numel(keyU);
assert(KL > 0, 'Key must contain at least one letter A-Z.');

% Sorted key and column order
[~, Idx] = sort(double(keyU));
skey = char(sort(keyU));

% Grid geometry
if TL == 0
    RL = 0;
    remLast = 0;
else
    RL = ceil(TL / KL);
    remLast = mod(TL, KL);
    if remLast == 0
        remLast = KL;
    end
end

switch direction
    case 1 % ====================== ENCRYPT ======================
        out.plain = text;
        out.key = keyU;

        if TL == 0
            out.encrypted = '';
            return;
        end

        % Build original grid M (RL-by-KL), row-wise fill, pad with spaces
        totalCells = RL * KL;
        if totalCells > TL
            ctextPad = [ctext, repmat(' ', 1, totalCells - TL)];
        else
            ctextPad = ctext;
        end
        M = reshape(ctextPad, KL, []).';

        % Columnar transposition
        M1 = M(:, Idx);

        % Vigenere row-wise using the sorted key (left-justified output)
        M2 = repmat(' ', size(M1));
        for I = 1:RL
            vout = vigenere(M1(I, :), skey, 1);
            L = length(vout.encrypted);
            if L > 0
                M2(I, 1:L) = vout.encrypted;
            end
        end

        % Extract ciphertext in blocks of up to 5 rows, column-by-column
        txt = '';
        rowStart = 1;
        while rowStart <= RL
            stop = min(5, RL - rowStart + 1);
            block = M2(rowStart:rowStart+stop-1, :);

            m = reshape(block, 1, []);
            m(m == ' ') = [];
            txt = [txt, m]; %#ok<AGROW>

            rowStart = rowStart + stop;
        end

        out.encrypted = txt;

    case -1 % ====================== DECRYPT ======================
        out.encrypted = text;
        out.key = keyU;

        if TL == 0
            out.plain = '';
            return;
        end

        % Left-justified validity mask for M2
        validM2 = true(RL, KL);
        if remLast < KL
            validM2(RL, remLast+1:KL) = false;
        end

        % Reconstruct M2 by filling in extraction order
        M2 = repmat(' ', RL, KL);

        pos = 1;
        rowStart = 1;
        while rowStart <= RL
            stop = min(5, RL - rowStart + 1);
            rows = rowStart:(rowStart + stop - 1);

            for col = 1:KL
                for r = 1:numel(rows)
                    row = rows(r);
                    if validM2(row, col)
                        if pos <= TL
                            M2(row, col) = ctext(pos);
                            pos = pos + 1;
                        end
                    end
                end
            end

            rowStart = rowStart + stop;
        end

        % Mask of letter-bearing columns in the LAST row of M1
        % In original grid M, last-row letters are in columns 1..remLast.
        % After transposition M1 = M(:,Idx), column j of M1 comes from Idx(j).
        % Therefore last-row letters in M1 are where Idx(j) <= remLast.
        lastRowLetterCols = (Idx <= remLast);

        % Apply Vigenere decryption row-wise using the sorted key
        % Then rebuild M1 with special handling for the last row
        M1 = repmat(' ', RL, KL);

        for I = 1:RL
            vout = vigenere(M2(I, :), skey, -1);
            prow = vout.plain;
            L = length(prow);

            if I < RL
                if L > 0
                    M1(I, 1:min(L, KL)) = prow(1:min(L, KL));
                end
            else
                % Last row: restore scattered positions in M1
                rowTmp = repmat(' ', 1, KL);
                cols = find(lastRowLetterCols);

                Luse = min(L, numel(cols));
                if Luse > 0
                    rowTmp(cols(1:Luse)) = prow(1:Luse);
                end

                M1(I, :) = rowTmp;
            end
        end

        % Reverse columnar transposition
        [~, invIdx] = sort(Idx);
        M = M1(:, invIdx);

        % Read row-wise, remove spaces, and trim to TL letters
        plainSeq = reshape(M.', 1, []);
        plainSeq(plainSeq == ' ') = [];
        if numel(plainSeq) > TL
            plainSeq = plainSeq(1:TL);
        end

        out.plain = plainSeq;
end
end
