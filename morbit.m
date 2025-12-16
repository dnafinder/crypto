function out = morbit(text,key,direction)
% MORBIT Cipher encoder/decoder
% 
% Morbit is an ACA cipher that combines:
%   1) Fractionated Morse:
%        - Letters/digits are converted to Morse.
%        - 'x' between letters, 'xx' between words.
%   2) A 9-digit numeric ciphertext derived from a 9-letter keyword
%      and a fixed 2×9 Morse pair tableau.
%
% The 2×9 Morse pair tableau is (fixed):
%   Row 1: . . . - - - x x x
%   Row 2: . - x . - x . - x
%
% For a 9-letter key (e.g. WISECRACK), the letters are ranked
% alphabetically (stable for duplicates) to give a digit 1–9 per
% column. Each Morse pair (column) is thus mapped to the corresponding
% digit via that column’s rank.
%
% Encryption (direction = 1)
%   - Plaintext → Morse (with x/xx separators).
%   - Morse stream is taken in pairs, forming a sequence of 2-symbol
%     pairs.
%   - Each pair is mapped to a column of the tableau, then to its digit
%     (1–9) via the key ranking → ciphertext digits.
%
% Decryption (direction = -1)
%   - Remove all non-digit characters from the input.
%   - Each digit (1–9) is converted back to the Morse pair via the
%     key ranking and the fixed tableau.
%   - The Morse stream is then parsed using:
%       x  = letter separator
%       xx = word separator
%
% Only letters A–Z, digits 0–9, and spaces are supported in plaintext.
% Other characters are ignored in the transformation.
%
% Syntax:
%   out = morbit(text,key,direction)
%
% Input:
%   text      - char array, plaintext (direction = 1)
%               or ciphertext digits (direction = -1)
%   key       - 9-letter keyword (A–Z only; case-insensitive)
%   direction - 1 to encrypt, -1 to decrypt
%
% Output struct:
%   out.plain     - plaintext (uppercased, spaces preserved)
%   out.key       - used key (uppercased)
%   out.encrypted - ciphertext digits (as char array)
%
% Example (using a 9-letter key):
% out = morbit('Hide the gold into the tree stump','WISECRACK',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'WISECRACK'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%     encrypted: '99184883198834321484818433267991675888193153754'
% 
% out = morbit('99184883198834321484818433267991675888193153754','WISECRACK',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'WISECRACK'
%     encrypted: '99184883198834321484818433267991675888193153754'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also: fmorse

% -------------------------------------------------------------------------
% Input parsing
% -------------------------------------------------------------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || isstring(x));
addRequired(p,'key', @(x) ischar(x) || isstring(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

text = char(text);
key  = upper(char(key));

% -------------------------------------------------------------------------
% Validate key (9 letters, A–Z; used for ranking 1..9)
% -------------------------------------------------------------------------
k_codes = double(key);
k_codes(k_codes < 65 | k_codes > 90) = []; % keep A–Z only
assert(numel(k_codes) == 9, ...
    'Key must be a 9-letter keyword containing only A–Z characters.');

% Rank letters alphabetically (stable) → digits 1..9
[~, idx_sorted] = sort(k_codes);  % stable sort, positions in original key
key_rank = zeros(1,9);
for i = 1:9
    key_rank(idx_sorted(i)) = i;  % position in sorted order → digit
end
clear idx_sorted i

out.key = char(k_codes);

% -------------------------------------------------------------------------
% Define fixed Morse pair tableau (2×9)
% Columns correspond to the 9 key positions. Each column is a pair
% (topRow(j), bottomRow(j)).
% -------------------------------------------------------------------------
topRow    = ['.','.','.','-','-','-','x','x','x'];
bottomRow = ['.','-','x','.','-','x','.','-','x'];

% -------------------------------------------------------------------------
% Main logic
% -------------------------------------------------------------------------
switch direction
    case 1  % ENCRYPT
        % Preprocess plaintext: keep A–Z, 0–9, and spaces
        pt = upper(text);
        % We preserve spaces explicitly; strip other non [A–Z0–9 ].
        mask_keep = (pt >= 'A' & pt <= 'Z') | ...
                    (pt >= '0' & pt <= '9') | ...
                    (pt == ' ');
        pt = pt(mask_keep);
        out.plain = pt;

        % ---- 1) Convert plaintext to Morse with x/xx separators ----
        morse = localTextToMorse(pt);

        % Ensure even length by padding with a single 'x' if needed
        if mod(numel(morse),2) ~= 0
            morse(end+1) = 'x';
        end

        % ---- 2) Form Morse pairs and map to digits ----
        nPairs = numel(morse)/2;
        digits = zeros(1,nPairs,'uint8');

        for k = 1:nPairs
            a = morse(2*k-1);  % top symbol
            b = morse(2*k);    % bottom symbol

            colMask = (topRow == a) & (bottomRow == b);
            col = find(colMask,1,'first');
            assert(~isempty(col), ...
                'Invalid Morse pair "%c%c" encountered during encryption.',a,b);

            d = key_rank(col);         % digit 1..9
            digits(k) = uint8('0') + uint8(d);
        end

        out.encrypted = char(digits);

    case -1 % DECRYPT
        % Extract digits only (ignore spaces and any other separators)
        ct = text(:).'; % row vector
        digitMask = (ct >= '0' & ct <= '9');
        ctd = ct(digitMask);
        assert(~isempty(ctd), ...
            'Ciphertext must contain digits 1–9.');

        % Convert digits to Morse pairs using key_rank + tableau
        morse = '';
        for k = 1:numel(ctd)
            d = double(ctd(k)) - double('0'); % numeric digit
            assert(d >= 1 && d <= 9, ...
                'Ciphertext digits must be in the range 1–9.');

            col = find(key_rank == d,1,'first');
            assert(~isempty(col), ...
                'Digit %d not consistent with key ranking.', d);

            morse = [morse, topRow(col), bottomRow(col)]; %#ok<AGROW>
        end

        % Optionally strip trailing padding 'x' (at most one, added in encrypt)
        if ~isempty(morse) && morse(end) == 'x'
            morse(end) = [];
        end

        % ---- Convert Morse with x/xx separators back to text ----
        pt = localMorseToText(morse);
        out.encrypted = ct;
        out.plain     = pt;
end

end

% =========================================================================
% Local helper: plaintext (A–Z, 0–9, space) → Morse with x/xx separators
% =========================================================================
function morse = localTextToMorse(pt)
% Morse tables (ITU-like)
morseL  = {'.-','-...','-.-.','-..','.','..-.','--.','....','..', ...
           '.---','-.-','.-..','--','-.','---','.--.','--.-','.-.', ...
           '...','-','..-','...-','.--','-..-','-.--','--..'};

morseD  = {'-----','.----','..---','...--','....-','.....', ...
           '-....','--...','---..','----.'};

morse = '';
prevWasSpace = true; % so first letter does not get a leading x

for i = 1:numel(pt)
    ch = pt(i);

    if ch == ' '
        % Word separator: ensure exactly "xx" between words.
        % If the last char in morse is already 'x', add one more.
        if ~isempty(morse) && morse(end) == 'x'
            morse = [morse 'x']; %#ok<AGROW>
        else
            morse = [morse 'xx']; %#ok<AGROW>
        end
        prevWasSpace = true;
        continue
    end

    % Letter / digit
    if ch >= 'A' && ch <= 'Z'
        idx = ch - 'A' + 1;
        code = morseL{idx};
    elseif ch >= '0' && ch <= '9'
        idx = ch - '0' + 1;
        code = morseD{idx};
    else
        % unsupported symbol – skip
        continue
    end

    % Insert 'x' between letters in the same word
    if ~prevWasSpace && ~isempty(morse) && morse(end) ~= 'x'
        morse = [morse 'x']; %#ok<AGROW>
    end

    morse = [morse code]; %#ok<AGROW>
    prevWasSpace = false;
end

end

% =========================================================================
% Local helper: Morse with x/xx separators → plaintext (A–Z, 0–9, space)
% =========================================================================
function pt = localMorseToText(morse)
letters = 'A':'Z';
morseL  = {'.-','-...','-.-.','-..','.','..-.','--.','....','..', ...
           '.---','-.-','.-..','--','-.','---','.--.','--.-','.-.', ...
           '...','-','..-','...-','.--','-..-','-.--','--..'};

digits  = '0':'9';
morseD  = {'-----','.----','..---','...--','....-','.....', ...
           '-....','--...','---..','----.'};

pt = '';
buffer = '';
i = 1;
N = numel(morse);

while i <= N
    if morse(i) == 'x'
        % Check if this is a word separator ("xx")
        if i < N && morse(i+1) == 'x'
            % End of current letter (if any)
            if ~isempty(buffer)
                pt = [pt, localDecodeSymbol(buffer,letters,morseL,digits,morseD)]; %#ok<AGROW>
                buffer = '';
            end
            % Add space
            pt = [pt, ' ']; %#ok<AGROW>
            i = i + 2;
        else
            % Single 'x' = letter separator
            if ~isempty(buffer)
                pt = [pt, localDecodeSymbol(buffer,letters,morseL,digits,morseD)]; %#ok<AGROW>
                buffer = '';
            end
            i = i + 1;
        end
    else
        buffer = [buffer, morse(i)]; %#ok<AGROW>
        i = i + 1;
    end
end

% Final symbol if pending
if ~isempty(buffer)
    pt = [pt, localDecodeSymbol(buffer,letters,morseL,digits,morseD)];
end

end

% =========================================================================
% Local helper: decode one Morse symbol into a single char
% =========================================================================
function ch = localDecodeSymbol(sym,letters,morseL,digits,morseD)
% Try letters first
idx = find(strcmp(sym,morseL),1,'first');
if ~isempty(idx)
    ch = letters(idx);
    return
end

% Try digits
idx = find(strcmp(sym,morseD),1,'first');
if ~isempty(idx)
    ch = digits(idx);
    return
end

% Fallback for unsupported pattern
ch = '?';
end
