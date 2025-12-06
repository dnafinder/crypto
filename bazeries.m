function out=bazeries(text,key,direction)
% BAZERIES Cipher encoder/decoder
% A simple substitution with trasposition. The Bazeries Cipher is a
% ciphering system created by Etienne Bazeries combining two grids
% (Polybius), and one key creating super-encryption.
% One of the squares features the alphabet written vertically in order. For
% the other square, choose a number less than a million, spell it out, and
% use it as the keyword for the other Polybius square, written
% horizontally. Finally, take the plaintext and split it into groups, with
% each group being the length of each digit in the key number. Reverse
% the text in each group. The normal alphabet Polybius square represents
% the plaintext letter, and the keyed horizontal Polybius square represents
% the ciphertext letter to replace it with.
%
% Syntax: 	out=bazeries(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is a characters array of the digits used as key.
%                 Digits must be 1-9 only; key value must be < 1 million.
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
% out=bazeries('Hide the gold into the tree stump','81257',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: '81257'
%     encrypted: 'OMDKMVBDCVGKCKWBRMMUKMDQNXK'
%
% out=bazeries('OMDKMVBDCVGKCKWBRMMUKMDQNXK','81257',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'OMDKMVBDCVGKCKWBRMMUKMDQNXK'
%           key: '81257'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also polybius, num2words
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% Ensure char row vectors
text = char(text);
key  = char(key);
key  = key(:)';

% Validate key: digits only, no zeros
assert(~isempty(key),'Key must be a non-empty char vector of digits.')
assert(~isempty(regexp(key,'^[1-9]+$','once')),'Key must contain digits 1-9 only (no zeros).')

nk = str2double(key);
assert(~isnan(nk) && isfinite(nk),'Key must be numeric.')
assert(nk < 1e6,'Key must be less than 1 million.')

% Preprocess text: uppercase letters only, J -> I
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];
ctext(ctext == 74) = 73;
ctext = char(ctext);

LT = length(ctext);

out.key = upper(key);

% Handle empty text after preprocessing
if LT == 0
    switch direction
        case 1
            out.plain = '';
            out.encrypted = '';
        case -1
            out.encrypted = '';
            out.plain = '';
    end
    return
end

% Convert key into digit vector
K  = double(key) - 48;
LK = length(K);

% Base alphabet without J
A = [65:1:73 75:1:90];

% Build squares depending on direction
switch direction
    case 1
        out.plain = ctext;

        % Plaintext square: alphabet written vertically in order
        PS1 = char(reshape(A,5,5));

        % Keyed square from spelled-out number
        w = upper(num2words(nk));
        w = regexprep(w,'[^A-Z]','');
        ckey = unique(w,'stable');
        ckey = double(ckey);
        ckey(ckey == 74) = 73; % J -> I if present
        ckey = unique(ckey,'stable');

        PS2 = reshape([ckey A(~ismember(A,ckey))],[5,5])';
        PS2 = char(PS2);

    case -1
        out.encrypted = ctext;

        % Ciphertext square: alphabet written vertically in order
        PS2 = char(reshape(A,5,5));

        % Keyed square from spelled-out number
        w = upper(num2words(nk));
        w = regexprep(w,'[^A-Z]','');
        ckey = unique(w,'stable');
        ckey = double(ckey);
        ckey(ckey == 74) = 73; % J -> I if present
        ckey = unique(ckey,'stable');

        PS1 = reshape([ckey A(~ismember(A,ckey))],[5,5])';
        PS1 = char(PS1);
end

% Group reversal governed by key digits (cyclic)
flag = true;
startIdx = 1;
iKey = 1;

while flag
    stopIdx = startIdx + K(iKey) - 1;

    if stopIdx >= LT
        stopIdx = LT;
        flag = false;
    end

    ctext(startIdx:stopIdx) = fliplr(ctext(startIdx:stopIdx));

    startIdx = stopIdx + 1;
    iKey = iKey + 1;

    if iKey > LK
        iKey = 1;
    end
end

% Substitution via corresponding coordinates
for i = 1:LT
    [R,C] = find(PS1 == ctext(i),1,'first');
    ctext(i) = PS2(R,C);
end

switch direction
    case 1
        out.encrypted = ctext;
    case -1
        out.plain = ctext;
end

end
