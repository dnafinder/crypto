function out = autokey(text,key,direction)
% AUTOKEY Cipher encoder/decoder
% An autokey cipher is a cipher which incorporates the message (the
% plaintext) into the key. The key is generated from the message in some
% automated fashion, sometimes by selecting certain letters from the text,
% or more commonly, by adding a short primer key to the front of the
% message.
% Consider an example message "MEET AT THE FOUNTAIN" encrypted with the
% primer keyword "KILT": to start, we would construct the autokey by
% placing the primer at the front of the message, using then the Vigenère
% algorithm.
% plaintext:  MEETATTHEFOUNTAIN
% key:        KILTMEETATTHEFOUN
% ciphertext: WMPMMXXAEYHBRYOCA
%
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=autokey(text,key,direction)
%
%     Input:
%           text - It is a characters array or string scalar to encode or decode
%           key - It is the primer keyword
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
% out=autokey('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'SMSVTJLGIYKQQXHALKHCHMFMIFW'
%
% out=autokey('SMSVTJLGIYKQQXHALKHCHMFMIFW','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'SMSVTJLGIYKQQXHALKHCHMFMIFW'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also beaufort, dellaporta, gronsfeld, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub: https://github.com/dnafinder/crypto

p = inputParser;

addRequired(p,'text',@(x) (ischar(x) && isrow(x)) || (isstring(x) && isscalar(x)));
addRequired(p,'key', @(x) (ischar(x) && isrow(x)) || (isstring(x) && isscalar(x)));
addRequired(p,'direction', @(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));

parse(p,text,key,direction);

% Normalize inputs to char:
text = char(text);
key  = char(key);

% Set all letters in uppercase and convert into ASCII Code.
ctext = double(upper(text));
ckey  = double(upper(key));

% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90) = [];
ckey(ckey<65 | ckey>90) = [];

assert(~isempty(ckey),'Key must contain at least one alphabetic character (A-Z).')

switch direction
    case 1 % Encrypt
        % Build autokey stream: primer + plaintext (both cleaned)
        keystream = [ckey ctext];
        keystream = keystream(1:numel(ctext));

        % Use Vigenere algorithm for encryption
        tmp = vigenere(char(ctext), char(keystream), 1);

        out.plain     = char(ctext);
        out.key       = char(ckey);
        out.encrypted = tmp.encrypted;

    case -1 % Decrypt
        LT = numel(ctext);
        LK = numel(ckey);

        % Iterative reconstruction of plaintext:
        % key chars are primer for first LK letters, then recovered plaintext.
        c = ctext - 65;          % 0..25
        k = ckey  - 65;          % 0..25

        pnum = zeros(1,LT);

        for i = 1:LT
            if i <= LK
                ki = k(i);
            else
                ki = pnum(i-LK);
            end
            pnum(i) = mod(c(i) - ki, 26);
        end

        out.encrypted = char(ctext);
        out.key       = char(ckey);
        out.plain     = char(pnum + 65);
end

end
