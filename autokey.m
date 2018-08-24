function out=autokey(text,key,direction)
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
% Syntax: 	out=autokey(text,key,direction)
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
% out=autokey('attack the east wall at dawn','queen',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'ATTACKTHEEASTWALLATDAWN'
%           key: 'QUEEN'
%     encrypted: 'QNXEPKMAEGKLAAELDTPDLHN'
%
% out=autokey('QNXEPKMAEGKLAAELDTPDLHN','QUEEN',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'QNXEPKMAEGKLAAELDTPDLHN'
%           key: 'QUEEN'
%         plain: 'ATTACKTHEEASTWALLATDAWN'
%
% See also beaufort, dellaporta, gronsfeld, trithemius, vigenere
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
        %Take primer and text to cover all the text
        tmp=[ckey ctext]; tmp=tmp(1:length(ctext));
        %use Vigenère algorithm
        out=vigenere(text,char(tmp),1);
        out.key=char(ckey);
    case -1 %Decrypt
        LT=length(ctext); LK=length(ckey); R=floor(LT/LK); keystream=key;
        plaintext='';
        % use Vigenère algorithm to decrypt R blocks of LK length.
        for I=1:R
            tmp=vigenere(char(ctext(I*LK-LK+1:I*LK)),keystream,-1);
            keystream=tmp.plain;
            plaintext=strcat(plaintext,keystream);
        end
        % use Vigenère algorithm to decrypt the remaining cryptogram
        tmp=strcat(key,plaintext); tmp=tmp(1:LT);
        tmp=vigenere(char(ctext(LK*R+1:LT)),tmp(LK*R+1:LT),-1);
        out.encrypted=text;
        out.key=char(ckey);
        out.plain=strcat(plaintext,tmp.plain);
end