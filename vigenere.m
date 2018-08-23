function out=vigenere(text,key,direction)
% VIGENERE CIPHER encoder/decoder
% The Vigenère cipher is a method of encrypting alphabetic text by using a
% series of interwoven Caesar ciphers based on the letters of a keyword. It
% is a form of polyalphabetic substitution. Though the cipher is easy to
% understand and implement, for three centuries it resisted all attempts to
% break it; this earned it the description le chiffre indéchiffrable
% (French for 'the indecipherable cipher'). 
%
% Syntax: 	out=vigenere(text,key,direction)
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
% out=vigenere('We are discovered flee at once','kingstonpower',1)
%
% out = 
% 
%   struct with fields:
% 
%        plain: 'WEAREDISCOVEREDFLEEATONCE'
%          key: 'KINGSTONPOWER'
%    encrypted: 'GMNXWWWFRCRIIOLSRWXOGDBYI'
%
% out=vigenere('GMNXWWWFRCRIIOLSRWXOGDBYI','KINGSTONPOWER',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'GMNXWWWFRCRIIOLSRWXOGDBYI'
%           key: 'KINGSTONPOWER'
%         plain: 'WEAREDISCOVEREDFLEEATONCE'
%
% See also autokey, beaufort, dellaporta, gronsfeld, nihilist, trithemius 
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

% Set all letters in uppercase and convert into ASCII Code.
text=double(upper(text));
key=double(upper(key)); 
% Erase all characters that are not into the range 65 - 90
text(text<65 | text>90)=[];
key(key<65 | key>90)=[];

switch direction
    case 1
        out.plain=char(text); 
    case -1
        out.encrypted=char(text);
end
out.key=char(key); 

% Repeat the key since covering all the text
LT=length(text); LK=length(key); RL=ceil(LT/LK); 
key2=repmat(key,1,RL); key2=key2(1:LT);
clear LT LK RL 

% Vigenère can also be described algebraically using modular arithmetic by
% first transforming the letters into numbers, according to the scheme, 
% A → 0, B → 1, ..., Z → 25. Encryption of a letter x using k key is
% described mathematically as:
% En(x) = (x+k) mod 26.
% Decryption is performed similarly,
% Dn(x) = (x−k) mod 26.

fun=@(t,k,d) char(65+mod((t-65+(k-65)*d),26));
switch direction 
    case 1 %Encrypt
        out.encrypted=fun(text,key2,direction);
    case -1 %Decrypt
        out.plain=fun(text,key2,direction);
end