function out = pollux(text,direction,varargin)
% POLLUX Cipher encoder/decoder
% The Pollux cipher is a Morse-based cipher in which Morse symbols
% (dots, dashes, separators) are replaced by decimal digits taken from
% three disjoint digit sets. Dots, dashes, and Morse separators are
% each mapped to their own pool of digits, typically in a round-robin
% fashion. The result is a digit-only ciphertext with no explicit
% Morse symbols remaining.
%
% This implementation:
%   - Uses ITU Morse code for A–Z and digits 0–9.
%   - Ignores all characters except A–Z and 0–9 in the plaintext.
%   - Inserts a '/' separator between Morse letters.
%   - Encodes:
%       '.'  → digits in DOTSET
%       '-'  → digits in DASHSET
%       '/'  → digits in SPACESET
%   - Assigns digits from each set cyclically (round-robin).
%   - Requires the same three digit sets for decryption.
%
% Syntax:
%   out = pollux(text,direction)
%   out = pollux(text,direction,dotset,dashset,spaceset)
%
% Input:
%   text      - Characters array to encode or decode.
%   direction - 1 to encrypt, -1 to decrypt.
%   dotset    - (optional) characters array of digits used for dots.
%   dashset   - (optional) characters array of digits used for dashes.
%   spaceset  - (optional) characters array of digits used for letter
%               separators.
%
%   If DOTSET, DASHSET, and SPACESET are omitted or empty and
%   direction == 1 (encrypt), the defaults are:
%       dotset   = '123'
%       dashset  = '456'
%       spaceset = '0789'
%
%   For decryption (direction == -1), all three sets are mandatory.
%   They must:
%       - contain only digits 0–9
%       - be nonempty
%       - be pairwise disjoint
%
% Output (struct):
%   out.plain     - Plain text (A–Z and digits only, uppercase).
%   out.encrypted - Cipher text (digits only).
%   out.dotset    - Digit set used for dots.
%   out.dashset   - Digit set used for dashes.
%   out.spaceset  - Digit set used for separators.
%
% Example:
% dotset   = '123';
% dashset  = '456';
% spaceset = '0789';
%
% out = pollux('Hide the gold into the tree stump',1,dotset,dashset,spaceset)
%
%   out =
%     struct with fields:
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%        dotset: '123'
%       dashset: '456'
%     spaceset: '0789'
%     encrypted: '1231023741283950123172864395640152376128319420576458693123017482539102731286931405672453'
%
%   out = pollux(out.encrypted,-1,dotset,dashset,spaceset)
%
%   out =
%     struct with fields:
%       encrypted: '1231023741283950123172864395640152376128319420576458693123017482539102731286931405672453'
%          dotset: '123'
%         dashset: '456'
%       spaceset: '0789'
%           plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'dotset',[],@(x) isempty(x) || (ischar(x) && all(x>='0' & x<='9')));
addOptional(p,'dashset',[],@(x) isempty(x) || (ischar(x) && all(x>='0' & x<='9')));
addOptional(p,'spaceset',[],@(x) isempty(x) || (ischar(x) && all(x>='0' & x<='9')));
parse(p,text,direction,varargin{:});
dotset   = p.Results.dotset;
dashset  = p.Results.dashset;
spaceset = p.Results.spaceset;
clear p

% Default sets for encryption if not provided
if direction == 1 && (isempty(dotset) || isempty(dashset) || isempty(spaceset))
    dotset   = '123';
    dashset  = '456';
    spaceset = '0789';
end

% Basic validation for decryption
if direction == -1
    assert(~isempty(dotset) && ~isempty(dashset) && ~isempty(spaceset),...
        'Dot, dash, and space digit sets are required to decrypt.');
end

% Normalize sets as row char arrays
dotset   = char(dotset);
dashset  = char(dashset);
spaceset = char(spaceset);

% Check that sets are nonempty and pairwise disjoint
assert(~isempty(dotset) && ~isempty(dashset) && ~isempty(spaceset),...
    'Dot, dash, and space digit sets must be nonempty.');

assert(~any(ismember(dotset,[dashset spaceset])) && ...
       ~any(ismember(dashset,spaceset)),...
       'Dot, dash, and space digit sets must be pairwise disjoint.');

% -------------------- Common setup --------------------
% ITU Morse code map for A–Z and 0–9
letters = ['A':'Z' '0':'9'];
morse = {...
    '.-','-...','-.-.','-..','.', '..-.','--.','....','..','.---',... % A–J
    '-.-','.-..','--','-.','---','.--.','--.-','.-.','...','-', ...    % K–T
    '..-','...-','.--','-..-','-.--','--..', ...                      % U–Z
    '-----','.----','..---','...--','....-','.....','-....','--...',...% 0–7
    '---..','----.'};                                                 % 8–9

% Normalize input text and keep only A–Z, 0–9
ctext = double(upper(text));
mask  = (ctext>=65 & ctext<=90) | (ctext>=48 & ctext<=57);
ctext = ctext(mask);
text_clean = char(ctext);
clear mask

switch direction
    case 1
        out.plain = text_clean;
    case -1
        out.encrypted = text_clean;
end

out.dotset   = dotset;
out.dashset  = dashset;
out.spaceset = spaceset;

% -------------------- Encrypt --------------------
if direction == 1
    if isempty(text_clean)
        out.encrypted = '';
        return
    end

    L = length(text_clean);

    % Build Morse string with '/' as letter separator
    mparts = cell(1,2*L-1);
    idxp = 1;
    for k = 1:L
        ch = text_clean(k);
        pos = find(letters == ch,1,'first');
        assert(~isempty(pos),'Unsupported character "%s" for Morse mapping.',ch);
        mparts{idxp} = morse{pos};
        idxp = idxp + 1;
        if k < L
            mparts{idxp} = '/';
            idxp = idxp + 1;
        end
    end
    morse_str = [mparts{:}];
    clear mparts idxp L

    % Map Morse symbols to digit sets (round-robin within each set)
    ndot   = length(dotset);
    ndash  = length(dashset);
    nspace = length(spaceset);

    idot = 1;
    idash = 1;
    ispace = 1;

    Lm = length(morse_str);
    cipher = char(zeros(1,Lm));

    for k = 1:Lm
        switch morse_str(k)
            case '.'
                cipher(k) = dotset(idot);
                idot = idot + 1;
                if idot > ndot, idot = 1; end
            case '-'
                cipher(k) = dashset(idash);
                idash = idash + 1;
                if idash > ndash, idash = 1; end
            case '/'
                cipher(k) = spaceset(ispace);
                ispace = ispace + 1;
                if ispace > nspace, ispace = 1; end
            otherwise
                error('Unexpected Morse symbol encountered during encryption.');
        end
    end

    out.encrypted = cipher;
    clear cipher morse_str ndot ndash nspace idot idash ispace
    return
end

% -------------------- Decrypt --------------------
if isempty(text_clean)
    out.plain = '';
    return
end

allowed = [dotset dashset spaceset];
assert(all(ismember(text_clean,allowed)),...
    'Ciphertext contains digits not present in the union of the three digit sets.');

% Map digits back to Morse symbols
Lm = length(text_clean);
morse_str = repmat(' ',1,Lm);

for k = 1:Lm
    ch = text_clean(k);
    if any(ch == dotset)
        morse_str(k) = '.';
    elseif any(ch == dashset)
        morse_str(k) = '-';
    elseif any(ch == spaceset)
        morse_str(k) = '/';
    else
        error('Unexpected digit in ciphertext at position %d.',k);
    end
end
clear k Lm allowed

% Split Morse string into letter codes using '/'
tokens = strsplit(morse_str,'/');
numTok = numel(tokens);

% Reverse Morse lookup
plain_buf = '';

for k = 1:numTok
    tk = tokens{k};
    if isempty(tk)
        continue
    end
    pos = find(strcmp(morse,tk),1,'first');
    assert(~isempty(pos),...
        'Invalid Morse pattern "%s" encountered during decryption.',tk);
    plain_buf = [plain_buf letters(pos)]; %#ok<AGROW>
end

out.plain = plain_buf;
clear plain_buf tokens numTok morse_str

end
