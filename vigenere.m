function out=vigenere(text,key,direction)
% VIGENERE Cipher encoder/decoder
% The Vigenère cipher is a method of encrypting alphabetic text by using a
% series of interwoven Caesar ciphers based on the letters of a keyword. It
% is a form of polyalphabetic substitution. Though the cipher is easy to
% understand and implement, for three centuries it resisted all attempts to
% break it; this earned it the description le chiffre indéchiffrable
% (French for 'the indecipherable cipher').
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=vigenere(text,key,direction)
%
%     Input:
%           text - It is a characters array (or string scalar) to encode or decode
%           key - It is the keyword (characters array or string scalar)
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
% out=vigenere('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'SMSVTJLGIYOMCKOVOENEPIHKUOW'
%
% out=vigenere('SMSVTJLGIYOMCKOVOENEPIHKUOW','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'SMSVTJLGIYOMCKOVOENEPIHKUOW'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also autokey, beaufort, dellaporta, gronsfeld, nihilist, trithemius, progressivekey
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
clear p

if isstring(text), text = char(text); end
if isstring(key),  key  = char(key);  end

% Set all letters in uppercase and convert into ASCII Code.
ctext = double(upper(text));
ckey  = double(upper(key));

% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90) = [];
ckey(ckey<65  | ckey>90)  = [];

assert(~isempty(ckey),'Key must contain at least one alphabetic letter A-Z')

switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end
out.key = char(ckey);

LT = numel(ctext);
LK = numel(ckey);

% Handle empty cleaned text gracefully
if LT == 0
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% Repeat the key to cover all the text
RL = ceil(LT/LK);
key_stream = repmat(ckey,1,RL);
key_stream = key_stream(1:LT);

% Vigenère in modular arithmetic:
% En(x) = (x+k) mod 26
% Dn(x) = (x−k) mod 26
fun = @(t,k,d) char(65 + mod((t-65) + d.*(k-65), 26));

switch direction
    case 1 % Encrypt
        out.encrypted = fun(ctext,key_stream,1);
    case -1 % Decrypt
        out.plain = fun(ctext,key_stream,-1);
end

end
