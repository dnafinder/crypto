function out=rot(text,key,direction)
% ROT Cipher encoder/decoder
% Rot(ation) is one of the simplest and most widely known encryption
% techniques. It is a type of substitution cipher in which each letter in
% the plaintext is replaced by a letter some fixed number of positions down
% the alphabet. English, 26 letters, alphabet is used and all non-alphabet
% symbols are not transformed.  
% For example, with a left shift of 3, D would be replaced by A, E would
% become B, and so on. The method is named Caesar Cipher after Julius
% Caesar, who, according to Svetonius, used it with a shift of three to
% protect messages of military significance. While Caesar's was the first
% recorded use of this scheme, other substitution ciphers are known to have
% been used earlier. 
% As with all single-alphabet substitution ciphers, the ROT cipher is
% easily broken and in modern practice offers essentially no communication
% security.
%
% Syntax: 	out=rot(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the alphabet shift. Its absolute value indicates
%           the magnitude of the shift (between 1 and 25); the sign
%           indicates if the shift is toward right (+) or left (-). Of
%           course, key~=0 because this means no shift.
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
% out=rot('Giuseppe Cardillo',7,1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'GIUSEPPE CARDILLO'
%           key: 7
%     encrypted: 'NPBZLWWLJHYKPSSV'
%
% out=rot('NPBZLWWLJHYKPSSV',7,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'NPBZLWWLJHYKPSSV'
%           key: 7
%         plain: 'GIUSEPPECARDILLO'
%
% See also rot13, affine, atbash
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-25,'<=',25}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

% Set all letters in uppercase and convert into ASCII Code.
text=upper(text); ctext=double(text); 
% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90)=[];

% The encryption can also be represented using modular arithmetic by first
% transforming the letters into numbers, according to the scheme, A → 0, B →
% 1, ..., Z → 25. Encryption of a letter x by a shift n can be described
% mathematically as:
% En(x) = (x+n) mod 26.
% Decryption is performed similarly,
% Dn(x) = (x−n) mod 26.
fun=@(x,k,d) char(mod((x-65)+d*k,26)+65);

switch direction
    case 1 % encrypt
        out.plain=text;
        out.key=key;
        out.encrypted=fun(ctext,key,direction);
    case -1 % decrypt
        out.encrypted=text;
        out.key=key;
        out.plain=fun(ctext,key,direction);
end