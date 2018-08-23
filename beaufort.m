function out=beaufort(text,key,direction)
% BEAUFORT CIPHER encoder/decoder
% The Beaufort cipher is a substitution cipher similar to the Vigenère
% cipher, with a slightly modified enciphering mechanism and tableau. The
% Beaufort cipher is based on the Beaufort square which is essentially the
% same as a Vigenère square but in reverse order starting with the letter
% "Z" in the first row, where the first row and the last column serve the
% same purpose.
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
% out=beaufort('We are discovered flee at once','kingstonpower',1)
%
% out = 
% 
%   struct with fields:
% 
%        plain: 'WEAREDISCOVEREDFLEEATONCE'
%          key: 'KINGSTONPOWER'
%    encrypted: 'OENPOQGVNABAAGFIVOPOUBBUA'
%
% out=beaufort('OENPOQGVNABAAGFIVOPOUBBUA','KINGSTONPOWER',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'OENPOQGVNABAAGFIVOPOUBBUA'
%           key: 'KINGSTONPOWER'
%         plain: 'WEAREDISCOVEREDFLEEATONCE'
%
% See also autokey, dellaporta, gronsfeld, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

% Set all letters in uppercase and convert into ASCII Code.
ctext=double(upper(text)); 
ckey=double(upper(key)); 
% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90)=[]; 
ckey(ckey<65 | ckey>90)=[];

switch direction
    case 1 %Encrypt
        out.plain=char(ctext); 
    case -1 %Decrypt
        out.encrypted=char(ctext); 
end
out.key=char(ckey); 

% Repeat the key since covering all the text
LT=length(ctext); LK=length(ckey); RL=ceil(LT/LK); 
key2=repmat(ckey,1,RL); ckey2=key2(1:LT);
clear LT LK RL key2 

% Beaufort can also be described algebraically using modular arithmetic by
% first transforming the letters into numbers, according to the scheme, 
% A → 0, B → 1, ..., Z → 25. Encryption of a letter x using k key is
% described mathematically as:
% En(x) = (X-k) mod 26.
% Decryption is performed similarly (C is the crypted chars)
% Dn(x) = (C−k) mod 26.
fun=@(ctext,ckey) char(mod((ckey-ctext),26)+65);
switch direction
    case 1
        out.encrypted=fun(ctext,ckey2);
    case -1
        out.plain=fun(ctext,ckey2);
end