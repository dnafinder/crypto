function out=ragbaby(text,key,direction)
% RAGBABY Cipher encoder/decoder
% The Ragbaby cipher is a substitution cipher that encodes/decodes text
% using a keyed alphabet and a progressive shift tied to the position of
% each letter within its plaintext word and to the word order.
%
% The procedure can be described as a variable ROT over a keyed alphabet:
% 1) Build a keyed alphabet from KEY (duplicates removed, stable order),
%    then append the remaining letters A-Z.
% 2) Preserve spaces; remove non A-Z characters.
% 3) Number plaintext words in sequence: the first word starts at shift 1,
%    the second at shift 2, etc. Within each word, the shift increases by
%    1 for each subsequent letter.
% 4) For encryption, shift each plaintext letter to the right by its
%    assigned value in the keyed alphabet. For decryption, shift to the
%    left by the same value.
%
% Syntax: 	out=ragbaby(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the keyword
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Examples:
%
% out=ragbaby('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'UKIC WBC KVCM OILY ZGN LDBD LPMLI'
%
% out=ragbaby('UKIC WBC KVCM OILY ZGN LDBD LPMLI','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'UKIC WBC KVCM OILY ZGN LDBD LPMLI'
%           key: 'LEPRACHAUN'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also rot
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% Preprocess text: uppercase, preserve spaces, remove other non A-Z chars.
ctext = double(upper(text));
ctext(ctext == 32) = 0; % temporary marker for spaces
ctext((ctext < 65 & ctext ~= 0) | ctext > 90) = []; % keep only A-Z and spaces

% Preprocess key: uppercase A-Z only
ckey = double(upper(key));
ckey(ckey > 90 | ckey < 65) = [];
assert(~isempty(ckey),'Key must contain at least one letter A-Z.')

% Build a display-safe version of the preprocessed text (convert markers to spaces)
disptext = ctext;
disptext(disptext == 0) = 32;

switch direction
    case 1
        out.plain = char(disptext);
    case -1
        out.encrypted = char(disptext);
end
out.key = char(ckey);

% Build keyed alphabet
ckey = unique(ckey,'stable');
A = 65:1:90;
PS = [ckey A(~ismember(A,ckey))];

% Indices of letters (exclude spaces)
letterMask = (ctext ~= 0);
[~,IdxLetters] = ismember(ctext(letterMask), PS);

% Compute shifts per character position
wordIndex = 1;
shiftVal = 1;
L = length(ctext);
shifts = zeros(1,L);

for i = 1:L
    if ctext(i) == 0
        wordIndex = wordIndex + 1;
        shiftVal = wordIndex;
    else
        shifts(i) = shiftVal;
        shiftVal = shiftVal + 1;
    end
end
clear i L wordIndex shiftVal

% Apply variable ROT over keyed alphabet, preserving spaces
tmpOut = repmat(32,1,length(ctext)); % initialize with spaces
letterShifts = shifts(letterMask);

tmpOut(letterMask) = PS(mod((IdxLetters-1) + direction .* letterShifts, 26) + 1);

switch direction
    case 1
        out.encrypted = char(tmpOut);
    case -1
        out.plain = char(tmpOut);
end

clear A PS ckey ctext disptext IdxLetters letterMask letterShifts shifts tmpOut
