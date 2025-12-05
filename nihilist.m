function out=nihilist(x,key1,key2,ms)
% NIHILIST SUBSTITUTION Cipher encoder/decoder
% In the history of cryptography, the Nihilist cipher is a manually
% operated symmetric encryption cipher, originally used by Russian
% Nihilists in the 1880s to organize terrorism against the tsarist regime.
% The term is sometimes extended to several improved algorithms used much
% later for communication by the First Chief Directorate with its spies.
%
% First the encipherer constructs a Polybius square using a mixed alphabet.
% This is used to convert both the plaintext and a keyword to a series of
% two digit numbers. These numbers are then added together in the normal
% way to get the ciphertext, with the key numbers repeated as required.
% Because each symbol in both plaintext and key is used as a whole number
% without any fractionation, the basic Nihilist cipher is little more than
% a numerical version of the Vigenere cipher, with multiple-digit numbers
% being the enciphered symbols instead of letters. As such, it can be
% attacked by very similar methods. An additional weakness is that the use
% of normal addition (instead of modular addition) leaks further
% information.
%
% English alphabet is used.
% For ms = 5, only letters A-Z are processed; other characters are ignored.
% J is merged into I.
% For ms = 6, letters A-Z and digits 0-9 are processed; other characters
% are ignored.
%
% Syntax: 	out=nihilist(x,key1,key2,ms)
%
%     Input:
%           x - It can be a character array, a string scalar, or a numeric array.
%               In the first case it will be encoded; in the second case it
%               will be decoded.
%           key1 - It is the keyword used to generate Polybius Square.
%                  If ms is equal to 5, all J will be transformed into I.
%           key2 - It is the keyword used to perform addition
%           ms - this parameter can assume only two values:
%                   5 to use a 5x5 Polybius square (default)
%                   6 to use a 6x6 Polybius square
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.ms = the size of Polybius Square
%           out.key1 = the used key1
%           out.key2 = the used key2
%           out.encrypted = the coded text
%
% Examples:
%
% out=nihilist('Hide the gold into the tree stump','leprachaun','ghosts and goblins',5)
%
% out=nihilist([55 56 73 56 90 66 27 57 73 44 73 59 35 79 66 89 55 34 87 58 57 56 59 69 54 74 55],...
%              'leprachaun','ghosts and goblins',5)
%
% See also adfgx, adfgvx, bazeries, bifid, checkerboard1, checkerboard2,
% foursquares, nihilist2, playfair, polybius, trifid, twosquares, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

if nargin < 4 || isempty(ms)
    ms = 5;
end

assert(isnumeric(ms) && isscalar(ms) && ismember(ms,[5 6]), ...
    'Polybius matrix must be 5x5 or 6x6')

if isstring(x) && isscalar(x)
    x = char(x);
end
if isstring(key1) && isscalar(key1)
    key1 = char(key1);
end
if isstring(key2) && isscalar(key2)
    key2 = char(key2);
end

assert(ischar(key1),'key1 must be a char vector or a string scalar')
assert(ischar(key2),'key2 must be a char vector or a string scalar')

isEncrypt = ischar(x);
isDecrypt = isnumeric(x);

assert(isEncrypt || isDecrypt, ...
    'Input x must be a character array, a string scalar, or a numeric array.')

% -------- Filter text and keys according to ms --------
if isEncrypt
    ctext = filterText(x,ms);
    out.plain = char(ctext);
    textVec = ctext;
else
    assert(isreal(x) && all(isfinite(x(:))), ...
        'Input numeric array must be real and finite.')
    assert(all(mod(x(:),1)==0), ...
        'Input numeric array must contain integers only.')
    out.encrypted = x;
    textVec = x;
end

ckey1_raw = filterKey(key1,ms);
ckey2_raw = filterKey(key2,ms);

out.ms = ms;
out.key1 = char(ckey1_raw);
out.key2 = char(ckey2_raw);

% -------- Polybius square generation from Key1 --------
switch ms
    case 5
        A = [65:1:73 75:1:90]; % [ABCDEFGHIKLMNOPQRSTUVWXYZ]
    case 6
        A = [65:1:90 48:1:57]; % [ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]
end

ckey1 = unique(ckey1_raw,'stable');
PS = reshape([ckey1 A(~ismember(A,ckey1))],[ms,ms])';
clear A ckey1

% -------- Key2 encoding with PS --------
[~,locb] = ismember(ckey2_raw,PS);
[I,J] = ind2sub([ms,ms],locb);
outkey2 = I.*10 + J;
clear locb I J

assert(~isempty(outkey2), ...
    'key2 must contain at least one valid character for the selected Polybius square.')

% -------- Key2 padding to match text length --------
L = numel(textVec);
RL = ceil(L/numel(outkey2));
outkey3 = repmat(outkey2,1,RL);
out2 = outkey3(1:L);
clear RL outkey3 outkey2

if isEncrypt
    % -------- Plaintext encoding --------
    [~,locb] = ismember(textVec,PS);
    [I,J] = ind2sub([ms,ms],locb);
    out1 = I.*10 + J;
    clear locb I J

    out.encrypted = out1 + out2;

else
    % -------- Ciphertext subtraction --------
    out1 = x - out2;

    % Validate decoded coordinates
    I = fix(out1./10);
    J = out1 - I.*10;

    switch ms
        case 5
            assert(all(ismember(I(:),1:5)) && all(ismember(J(:),1:5)), ...
                'Ciphertext cannot be decoded using a 5x5 Polybius matrix with the given keys.')
        case 6
            assert(all(ismember(I(:),1:6)) && all(ismember(J(:),1:6)), ...
                'Ciphertext cannot be decoded using a 6x6 Polybius matrix with the given keys.')
    end

    Ind = sub2ind([ms,ms],I,J);
    out.plain = char(PS(Ind));
end

% ---------------- Local helpers ----------------
function vec = filterText(t,msLocal)
    t = upper(t);
    c = double(t);

    switch msLocal
        case 5
            c(c<65 | c>90) = [];
            c(c==74) = 73; % J -> I
        case 6
            c(c>57 & c<65) = [];
            c(c<48 | c>90) = [];
    end
    vec = c;
end

function vec = filterKey(k,msLocal)
    k = upper(k);
    c = double(k);

    switch msLocal
        case 5
            c(c<65 | c>90) = [];
            c(c==74) = 73; % J -> I
        case 6
            c(c>57 & c<65) = [];
            c(c<48 | c>90) = [];
    end
    vec = c;
end

end
