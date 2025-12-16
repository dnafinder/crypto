function out = fmorse(text,key,direction)
% FMORSE Fractionated Morse cipher encoder/decoder
% The Fractionated Morse cipher is a classical manual cipher that first
% encodes plaintext letters into Morse code, then "fractionates" this
% stream into fixed-size trigrams (groups of 3 symbols) and finally
% maps each trigram to a ciphertext letter using a keyed substitution
% alphabet.
%
% In this implementation:
% - Plaintext is restricted to letters A–Z (case-insensitive).
%   All other characters are ignored in the transformation.
% - Plaintext is converted to International Morse (letters only: A–Z).
% - Individual letters are separated by 'x' in the Morse stream.
% - The Morse stream is padded with up to two 'x' characters so that its
%   total length is a multiple of 3.
% - Each Morse trigram ('.','-','x') is mapped to a letter using a
%   keyed 26-letter substitution alphabet derived from KEYWORD logic:
%     - take the key, remove duplicate letters (preserving order)
%     - append the remaining letters A–Z not present in the key
% - Decryption performs the exact inverse steps:
%     ciphertext → trigrams → Morse stream → letters.
% - Word spacing is not preserved: output plaintext is returned as a
%   continuous A–Z string.
%
% Syntax:
%   out = fmorse(text,key,direction)
%
% Input:
%   text      - character array to encode or decode
%   key       - keyword used to derive the substitution alphabet
%   direction - numeric flag:
%                 1  to encrypt
%                -1  to decrypt
%
% Output (structure):
%   out.plain      - plaintext (A–Z only, uppercase)
%   out.key        - cleaned keyword (A–Z only, uppercase)
%   out.encrypted  - ciphertext (A–Z only, uppercase)
%
% Example:
%
%   out = fmorse('Hide the gold into the tree stump', 'leprachaun', 1)
%
% out = fmorse('Hide the gold into the tree stump', 'leprachaun', 1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'LHUPUQPUFISPBQVXIXLHXRTHPKCJAN'
% 
% out = fmorse('LHUPUQPUFISPBQVXIXLHXRTHPKCJAN', 'leprachaun', -1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'LHUPUQPUFISPBQVXIXLHXRTHPKCJAN'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also vigenere, gronsfeld, gromark, ragbaby, condi
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% ---------------------- Input parsing & validation ---------------------- %
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key', @(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% Clean and normalize text and key
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];        % keep only A–Z
ckey  = double(upper(key));
ckey(ckey < 65 | ckey > 90) = [];          % keep only A–Z

assert(~isempty(ckey),'Key must contain at least one letter A–Z');

switch direction
    case 1 % encrypt
        out.plain = char(ctext);
    case -1 % decrypt
        out.encrypted = char(ctext);
end
out.key = char(ckey);

% ---------------------- Build substitution alphabet -------------------- %
% KEYWORD-style alphabet: unique(key) + remaining letters A–Z
ckey = unique(ckey,'stable');
A = 65:1:90;
alpha = char([ckey A(~ismember(A,ckey))]);
clear A

% ---------------------- Morse code table (A–Z) ------------------------- %
% International Morse, letters only
letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
morseCodes = { ...
    '.-'   , ... % A
    '-...', ... % B
    '-.-.', ... % C
    '-..' , ... % D
    '.'   , ... % E
    '..-.', ... % F
    '--.' , ... % G
    '....', ... % H
    '..'  , ... % I
    '.---', ... % J
    '-.-' , ... % K
    '.-..', ... % L
    '--'  , ... % M
    '-.'  , ... % N
    '---' , ... % O
    '.--.', ... % P
    '--.-', ... % Q
    '.-.' , ... % R
    '...' , ... % S
    '-'   , ... % T
    '..-' , ... % U
    '...-', ... % V
    '.--' , ... % W
    '-..-', ... % X
    '-.--', ... % Y
    '--..'  ... % Z
    };

% ---------------------- Trigram list (fractionation) ------------------- %
% All trigrams over {'.','-','x'} except 'xxx', in lexicographic order
symbols = ['.' '-' 'x'];
triplets = cell(1,26);
idxTrip = 1;
for i = 1:3
    for j = 1:3
        for k = 1:3
            t = [symbols(i) symbols(j) symbols(k)];
            if ~strcmp(t,'xxx')
                triplets{idxTrip} = t;
                idxTrip = idxTrip + 1;
                if idxTrip > 26
                    break;
                end
            end
        end
        if idxTrip > 26
            break;
        end
    end
    if idxTrip > 26
        break;
    end
end
triplets = char(triplets); % 26 x 3
clear symbols idxTrip i j k

% ---------------------- Core logic: encrypt / decrypt ------------------ %
switch direction
    case 1  % ------------------------ Encrypt ------------------------ %
        % Convert plaintext letters to Morse stream with 'x' as letter separator
        L = numel(ctext);
        morse = '';
        for I = 1:L
            ch = char(ctext(I));
            pos = ch - 64; % 'A'->1
            % extra safety
            if pos < 1 || pos > 26
                continue;
            end
            code = morseCodes{pos};
            morse = [morse code]; %#ok<AGROW>
            if I < L
                morse = [morse 'x']; %#ok<AGROW>
            end
        end
        clear I L ch pos code

        % Pad Morse stream with up to 2 'x' to reach length multiple of 3
        LM = length(morse);
        pad = mod(3 - mod(LM,3),3);
        if pad > 0
            morse = [morse repmat('x',1,pad)];
        end
        clear LM pad

        % Split into trigrams
        if isempty(morse)
            out.encrypted = '';
            return
        end
        morseMat = reshape(morse,3,[])'; % each row = one trigram
        nTri = size(morseMat,1);
        cipher = repmat('A',1,nTri);

        % Map each trigram to a letter via substitution alphabet
        for I = 1:nTri
            t = morseMat(I,:);
            % find matching row in triplets
            row = find(all(bsxfun(@eq,triplets,t),2),1,'first');
            assert(~isempty(row), ...
                'Encountered a Morse trigram with no mapping; check implementation.');
            cipher(I) = alpha(row);
        end
        clear I nTri t row morse morseMat triplets alpha

        out.encrypted = cipher;

    case -1 % ------------------------ Decrypt ------------------------ %
        if isempty(ctext)
            out.plain = '';
            return
        end

        % Each ciphertext letter → trigram (via inverse of substitution alphabet)
        L = numel(ctext);
        morse = '';
        for I = 1:L
            ch = char(ctext(I));
            pos = find(alpha == ch,1,'first');
            assert(~isempty(pos), ...
                'Ciphertext letter not found in substitution alphabet.');
            morse = [morse triplets(pos,:)]; %#ok<AGROW>
        end
        clear I L ch pos triplets alpha

        % Strip trailing padding 'x' (never produced by actual encoding)
        while ~isempty(morse) && morse(end) == 'x'
            morse(end) = [];
        end

        % Parse Morse stream back into letters, splitting at 'x'
        plain = '';
        while ~isempty(morse)
            idx = find(morse == 'x',1,'first');
            if isempty(idx)
                segment = morse;
                morse = '';
            else
                segment = morse(1:idx-1);
                morse(1:idx) = []; % remove segment and separator
            end
            if isempty(segment)
                continue;
            end
            % Find which letter has this Morse code
            match = find(strcmp(segment,morseCodes),1,'first');
            assert(~isempty(match), ...
                'Decoded Morse segment has no matching letter; check implementation.');
            plain = [plain letters(match)]; %#ok<AGROW>
        end
        clear segment idx match morse morseCodes letters

        out.plain = plain;
end
end
