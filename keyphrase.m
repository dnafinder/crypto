function out=keyphrase(text,keyphrase,direction)
% KEYPHRASE Cipher encoder/decoder
% A key phrase cipher is a monoalphabetic substitution in which a full
% 26-letter pangram (the key phrase) is used directly as the cipher
% alphabet.
%
% The key phrase:
%   - must contain each letter A–Z exactly once (ignoring case and spaces)
%   - may contain spaces and punctuation, which are ignored when building
%     the cipher alphabet
%
% Plain alphabet:
%   A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
%
% Cipher alphabet (example):
%   T H E Q U I C K B R O W N F X J M P S V L A Z Y D G
% derived from the pangram:
%   "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
%
% Only letters A–Z are enciphered/deciphered; all other characters
% (spaces, punctuation, digits, etc.) are preserved as-is.
%
% Syntax:  out = keyphrase(text,keyphrase,direction)
%
%     Input:
%           text      - Character array to encode or decode.
%           keyphrase - Pangram used as cipher alphabet. After removing
%                      non-letter characters and collapsing case, it must
%                      contain each letter A–Z exactly once.
%           direction - Can assume only two values:
%                        1  to encrypt
%                       -1  to decrypt.
%
%     Output:
%           out - Structure with fields
%                 out.plain     = plain text (A–Z, uppercase; spacing preserved)
%                 out.key       = the used key phrase (as provided)
%                 out.encrypted = encoded text (A–Z, uppercase; spacing preserved)
%
% Example:
%
%   out = keyphrase('Hide the gold into the tree stump', ...
%                   'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 1)
%
%   out =
%
%     struct with fields:
%
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG'
%     encrypted: 'KBQU VKU CXWQ BFVX VKU VPUU SVLNJ'
%
%   out = keyphrase('KBQU VKU CXWQ BFVX VKU VPUU SVLNJ', ...
%                   'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', -1)
%
%   out =
%
%     struct with fields:
%
%     encrypted: 'KBQU VKU CXWQ BFVX VKU VPUU SVLNJ'
%           key: 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also keyword, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% -------------------------
% Input parsing
% -------------------------
p = inputParser;
addRequired(p,'text',      @(x) ischar(x));
addRequired(p,'keyphrase', @(x) ischar(x));
addRequired(p,'direction', @(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,keyphrase,direction);
clear p

% -------------------------
% Build cipher alphabet from key phrase
% -------------------------
% Keep only letters, uppercase
k = double(upper(keyphrase));
k = k(k>=65 & k<=90);           % A–Z

% Preserve first occurrence of each letter
if isempty(k)
    error('Key phrase is empty after removing non-letter characters.');
end
k_unique = unique(k,'stable');

% Enforce pangram: must contain each letter A–Z exactly once
assert(numel(k_unique) == 26 && all(ismember(k_unique,65:90)), ...
    'Key phrase must use each letter A–Z exactly once (pangram without duplicates).');

cipherAlpha = char(k_unique);           % Cipher alphabet
plainAlpha  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

% -------------------------
% Normalize text, prepare output
% -------------------------
t = upper(text);              % Work in uppercase
outText = t;                  % Preallocate output as a copy

switch direction
    case 1
        out.plain = t;
    case -1
        out.encrypted = t;
end
out.key = keyphrase;          % Preserve original phrase (with spaces etc.)

% -------------------------
% Core substitution
% -------------------------
L = length(t);
for I = 1:L
    ch = t(I);
    if ch >= 'A' && ch <= 'Z'
        switch direction
            case 1 % Encrypt: PT -> CT
                idx = double(ch) - 64;          % 'A'->1 ... 'Z'->26
                outText(I) = cipherAlpha(idx);
            case -1 % Decrypt: CT -> PT
                idx = find(cipherAlpha == ch, 1, 'first');
                if ~isempty(idx)
                    outText(I) = plainAlpha(idx);
                else
                    % Should not occur if ciphertext is consistent with key
                    % Leave character unchanged as a safeguard
                    outText(I) = ch;
                end
        end
    else
        % Non A–Z characters are preserved as-is
        outText(I) = ch;
    end
end

% -------------------------
% Finalize output
% -------------------------
switch direction
    case 1
        out.encrypted = outText;
    case -1
        out.plain = outText;
end