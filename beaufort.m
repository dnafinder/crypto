function out=beaufort(text,key,direction)
% BEAUFORT Cipher encoder/decoder
% The Beaufort cipher is a substitution cipher similar to the Vigenère
% cipher, with a modified enciphering mechanism and tableau. The Beaufort
% cipher is based on the Beaufort square which is essentially the same as a
% Vigenère square but in reverse order starting with the letter "Z" in the
% first row, where the first row and the last column serve the same purpose.
%
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=beaufort(text,key,direction)
%
%     Input:
%           text - It is a characters array (or string scalar) to encode or decode
%           key - It is the keyword (char vector or string scalar)
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
% out=beaufort('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'EWMNHVDUGCIWCYMJAWBWHAXYGQS'
%
% out=beaufort('EWMNHVDUGCIWCYMJAWBWHAXYGQS','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'EWMNHVDUGCIWCYMJAWBWHAXYGQS'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% Beaufort can be described algebraically using modular arithmetic by
% first transforming the letters into numbers, according to the scheme,
% A → 0, B → 1, ..., Z → 25.
% Encryption and decryption share the same rule:
% C = (K − P) mod 26
% P = (K − C) mod 26
%
% See also autokey, dellaporta, gronsfeld, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub: https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

text = char(text);
key  = char(key);

% Set all letters in uppercase and convert into ASCII Code.
ctext = double(upper(text));
ckey  = double(upper(key));

% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90) = [];
ckey(ckey<65  | ckey>90)  = [];

assert(~isempty(ckey),'Key must contain at least one alphabetic character')

LT = numel(ctext);
LK = numel(ckey);

% Prepare output fields consistently even for empty cleaned text.
if LT==0
    switch direction
        case 1
            out.plain = char(ctext);
            out.key = char(ckey);
            out.encrypted = '';
        case -1
            out.encrypted = char(ctext);
            out.key = char(ckey);
            out.plain = '';
    end
    return
end

% Repeat the key to cover all the text
key_stream = repmat(ckey,1,ceil(LT/LK));
key_stream = key_stream(1:LT);

fun = @(t,k) char(mod((k - t),26) + 65);

switch direction
    case 1 % Encrypt
        out.plain = char(ctext);
        out.key = char(ckey);
        out.encrypted = fun(ctext,key_stream);
    case -1 % Decrypt
        out.encrypted = char(ctext);
        out.key = char(ckey);
        out.plain = fun(ctext,key_stream);
end
end
