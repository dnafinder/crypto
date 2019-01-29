function out=dellaporta(text,key,direction)
% The Della Porta Cipher is a polyalphabetic substitution cipher invented by
% Giovanni Battista della Porta. Where the Vigenère cipher is a
% polyalphabetic cipher with 26 alphabets, the Porta is basically the same
% except it only uses 13 alphabets. The 13 cipher alphabets it uses are
% reciprocal, so enciphering is the same as deciphering.    
%
% Syntax: 	out=dellaporta(text,key,direction)
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
% out=dellaporta('Hide the gold into the tree stump','leprachaun',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'ZXXZGVUTERVXGLBFXRJLWTLLHNM'
%
% out=dellaporta('ZXXZGVUTERVXGLBFXRJLWTLLHNM','leprachaun',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'ZXXZGVUTERVXGLBFXRJLWTLLHNM'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also autokey, beaufort, gronsfeld, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% The Dalla Porta Cipher uses the following tableau:
% 
%   Keys| a b c d e f g h i j k l m n o p q r s t u v w x y z
%   ---------------------------------------------------------
%   A,B | n o p q r s t u v w x y z a b c d e f g h i j k l m
%   C,D | o p q r s t u v w x y z n m a b c d e f g h i j k l
%   E,F | p q r s t u v w x y z n o l m a b c d e f g h i j k 
%   G,H | q r s t u v w x y z n o p k l m a b c d e f g h i j
%   I,J | r s t u v w x y z n o p q j k l m a b c d e f g h i
%   K,L | s t u v w x y z n o p q r i j k l m a b c d e f g h
%   M,N | t u v w x y z n o p q r s h i j k l m a b c d e f g
%   O,P | u v w x y z n o p q r s t g h i j k l m a b c d e f
%   Q,R | v w x y z n o p q r s t u f g h i j k l m a b c d e
%   S,T | w x y z n o p q r s t u v e f g h i j k l m a b c d
%   U,V | x y z n o p q r s t u v w d e f g h i j k l m a b c
%   W,X | y z n o p q r s t u v w x c d e f g h i j k l m a b
%   Y,Z | z n o p q r s t u v w x y b c d e f g h i j k l m a

tr1=zeros(13,13); tr2=zeros(13,13);
tr1(1,:)=14:1:26; tr2(1,:)=1:1:13;
for I=2:13
    tr1(I,:)=circshift(tr1(I-1,:),-1);
    tr2(I,:)=circshift(tr2(I-1,:),1);
end
tr=[tr1 tr2]+64; 
clear I tr1 tr2

% Set all letters in uppercase and convert into ASCII Code.
% Erase all characters that are not into the range 65 - 90
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[];
ckey=double(upper(key)); ckey(ckey<65 | ckey>90)=[];

switch direction
    case 1 %encrypt
        out.plain=char(ctext);
    case -1 %decrypt
        out.encrypted=char(ctext);
end
out.key=char(ckey);

% Repeat the key since covering all the text
LT=length(ctext); LK=length(ckey); RL=ceil(LT/LK); 
key2=repmat(ckey,1,RL); key2=key2(1:LT);

% transform the letters into numbers, according to the scheme:  
% A → 1, B → 2, ..., Z → 26. 
ctext=ctext-64; ckey=key2-64;
clear LK RL key2
% Add one to all odd numbers in the key
ckey(mod(ckey,2)==1)=ckey(mod(ckey,2)==1)+1;
% divide by 2 so A,B = row 1; C,D = row 2 ... etc
ckey=ckey/2;

tmp=zeros(1,LT); %vector preallocation
switch direction
    case 1 %encrypt
        %find in the table
        for I=1:LT
            tmp(I)=tr(ckey(I),ctext(I));
        end
        out.encrypted=char(tmp);
    case -1 %decrypt
        %find in the table
        for I=1:LT
            tmp(I)=find(tr(ckey(I),:)==out.encrypted(I));
        end
        out.plain=char(tmp+64);
end