function out=cadenus(text,key,direction)
%CADENUS Cipher encoder/decoder
%Columnar tramp using a keyword to shift the order of the columns and, at
%the same time to shift the starting point of each column. The latter is
%done by attaching a letter of the alphabet (25-letter alphabetas shown
%with V and W in the same cell) to each row of plaintext in the block.
%A severe limitation of the usefulness of the Cadenus is that every message
%must be a multiple of twenty-five letters long and, as consequence, the
%key length must be the ratio of text length and 25.
%
% Syntax: 	out=cadenus(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is a characters array of the digits used as key.
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
% out=cadenus('the treasure is under the palm near the west cave under the great lion that sees the seaside','ear',1)
%
% out = 
% 
%   struct with fields:
% 
%           key: 'ear'
%         plain: 'the treasure is under the palm near the west cave under the great lion that…'
%     encrypted: 'HEERHTSEWEITUTVETNHARARENSERDLETNSPAAMEUATEHSHESRCETEEODEHTUSGISANEIRATEDTL'
%
% out=cadenus('HEERHTSEWEITUTVETNHARARENSERDLETNSPAAMEUATEHSHESRCETEEODEHTUSGISANEIRATEDTL','ear',-1)
%
% out = 
% 
%   struct with fields:
% 
%           key: 'ear'
%     encrypted: 'HEERHTSEWEITUTVETNHARARENSERDLETNSPAAMEUATEHSHESRCETEEODEHTUSGISANEIRATEDTL'
%         plain: 'THETREASUREISUNDERTHEPALMNEARTHEWESTCAVEUNDERTHEGREATLIONTHATSEESTHESEASIDE'
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
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; ctext=char(ctext);
% text length
LT=length(ctext);
% Check if LT is multiple of 25
R=mod(LT,25);
assert(R==0,'A severe limitation of the usefulness of the Cadenus is that every message must be a multiple of twenty-five letters long.\n You need %i letters more',25-R)
clear R

ckey=double(upper(key)); ckey(ckey<65 | ckey>90)=[];
% Convert W (ASCII code 87) into V (ASCII code 86)
ckey(ckey==87)=86;
% key Length
LK=length(ckey);
C=LT/25;
%Check if LK is the ratio of LT and 25
assert(C==LK,'The key must be %i letters long',C)

% reshape the text into a matrix 25xC
ctext=reshape(ctext,C,25)';
clear LK

switch direction
    case 1 %if you are encrypting, take ordered key and index
        [ckey,Idx]=sort(ckey);
    case -1 %if you are decrypting, take only the index
        [~,Idx]=sort(ckey);
end
%shuffle the columns
ctext=ctext(:,Idx);
clear Idx

%Shift the starting point of the columns
ckey2=double('AZYXVUTSRQPONMLKJIHGFEDCB');
for I=1:C
    S=find(ckey2==ckey(I),1,'first')-1;
    ctext(:,I)=circshift(ctext(:,I),-direction*S);
end
clear C I S ckey*
%reshape into a vector horizontally
ctext=reshape(ctext',1,LT);

out.key=key;
switch direction
    case 1
        out.plain=text;
        out.encrypted=ctext;
    case -1
        out.encrypted=text;
        out.plain=ctext;
end
clear ctext LT