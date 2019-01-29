function out=ragbaby(text,key,direction)
% RAGBABY Cipher encoder/decoder
% The ragbaby cipher is a substitution cipher that encodes/decodes a text
% using a keyed alphabet and their position in the plaintext word they are
% a part of.  It can be considered as a multiple ROT encoding/decoding.
%
% Syntax: 	out=ragbaby(text,key,direction)
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
% out=ragbaby('Hide the gold into the tree stump','leprachaun',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'UKIC WBC KVCM OILY ZGN LDBD LPMLI'
%
% out=ragbaby('UKIC WBC KVCM OILY ZGN LDBD LPMLI','leprachaun',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'UKIC WBC KVCM OILY ZGN LDBD LPMLI'
%           key: 'LEPRACHAUN'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also rot
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); 
ctext(ctext==32)=0; ctext((ctext<65 & ctext~=0)| ctext>90)=[]; %preserve spaces
ckey=double(upper(key)); ckey(ckey>90 | ckey<65)=[]; 

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end
out.key=char(ckey);

% Chars of the key must be choosen only once
ckey=unique(ckey,'stable'); 
A=65:1:90;
%if key is 'LEPRACHAUN' then PS=LEPRACHUNBDFGIJKMOQSTVWXYZ
PS=[ckey A(~ismember(A,ckey))];

[~,Idx]=ismember(ctext(ctext~=0),PS); %Index of inputed chars into PS
clear ckey A
%Number the letters of each plaintext word in sequence beginning with 1 for
%the first letter of the first word, 2 for the first letter of the second
%word, etc. Each plaintext letter is enciphered by moving to the right the
%designated number of spaces, using the letter found there as its substitute
S=1; J=1; L=length(ctext); tmp=zeros(1,L); tmp2=repmat(32,1,L);
for I=1:L
    if ctext(I)==0
        S=S+1; 
        J=S; 
    else
        tmp(I)=J; 
        J=J+1;
    end
end
clear J S L I ctext
%Use "rot" modular algebra
tmp2((tmp~=0))=PS(mod((Idx-1)+direction.*tmp(tmp~=0),26)+1);
clear PS tmp where
switch direction
    case 1
        out.encrypted=char(tmp2);
    case -1
        out.plain=char(tmp2);
end
clear tmp2