function out=trithemius(text,direction)
% TRITHEMIUS Cipher encoder/decoder
% The Trithemius cipher is a polyalphabetic encryption method invented by
% the German abbot Trithemius during the Renaissance. This code is a
% sequence of shifts: the first letter is not shifted, the second is
% shifted up by 1 in the alphabet, the third by 2, etc.
% With a classical alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ, Trithemius cipher
% is equivalent to a Vigenère cipher with ABCDEFGHIJKLMNOPQRSTUVWXYZ as
% key.
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=trithemius(text,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.encrypted = the coded text
%
% Examples:
%
% out=trithemius('Hide the gold into the tree stump',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%     encrypted: 'HJFHXMKNWUNTZGCIXVLKYZOQSLP'
%
% out=trithemius('HJFHXMKNWUNTZGCIXVLKYZOQSLP',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'HJFHXMKNWUNTZGCIXVLKYZOQSLP'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also vigenere, autokey, beaufort, dellaporta, gronsfeld
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,direction);
clear p

% Preprocessing: uppercase and keep only standard English letters A-Z
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];
ctext = char(ctext);

out = vigenere(ctext,'ABCDEFGHIJKLMNOPQRSTUVWXYZ',direction);
out = rmfield(out,'key');
