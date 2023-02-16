function out=condi(text,key,offset,direction)
%CONDI Cipher encoder/decoder
%The Condi uses a simple keyed alphabet and multiple ROT encoding, changing
%a monoalphabetic substitution into a polyalphabetic substitution.
%With a starter value or off-set of #, substitute the first plaintext
%letter by the letter found # places further along the alphabet. Then the
%position of that first plaintext letter is the new value for #, the
%off-set for the next plaintext letter. And so on. 
%
% Syntax: 	out=condi(text,key,offset,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the keyword to generate the alphabet
%           offset - It is the first alphabet shift. Its absolute value
%           indicates the magnitude of the shift (between 1 and 25); the
%           sign indicates if the shift is toward right (+) or left (-). Of
%           course, key~=0 because this means no shift.
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.offset = the used starting offset
%           out.encrypted = the coded text
%
% Examples:
%
% out=condi('Hide the gold into the tree stump','leprachaun',6,1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%        offset: 6
%     encrypted: 'GTYGWENJAQFYWRGGENWYCRVJPYS'
%
% out=condi('GTYGWENJAQFYWRGGENWYCRVJPYS','leprachaun',6,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'GTYGWENJAQFYWRGGENWYCRVJPYS'
%           key: 'LEPRACHAUN'
%        offset: 6
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also rot
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'offset',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-25,'<=',25}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,offset,direction);
clear p

% Set all letters in uppercase and convert into ASCII Code.
text=double(upper(text));
key=double(upper(key)); 
% Erase all characters that are not into the range 65 - 90
text(text<65 | text>90)=[];
key(key<65 | key>90)=[];
switch direction
    case 1 %encrypt
        out.plain=char(text);
    case-1
        out.encrypted=char(text);
end
out.key=char(key);
out.offset=offset;

% Chars of the key must be choosen only once
% then all the others into alphabetic order
ckey=unique(key,'stable');
A=65:1:90;
PS=char([ckey A(~ismember(A,ckey))]);
clear ckey A

L=length(text);
tmp=zeros(1,L);
%use modular arithmetic
fun=@(x,k,d) mod((x-1)+d*k,26)+1;
 for I=1:L
     x=find(PS==text(I),1,'first');
     tmp(I)=PS(fun(x,offset,direction));
     switch direction
         case 1 %encrypt
            offset=x;
         case -1 %decrypt
            offset=find(PS==tmp(I),1,'first');
     end
end
clear I L x offset PS fun
switch direction
    case 1 %encrypt
        out.encrypted=char(tmp);
    case -1 %decrypt
       out.plain=char(tmp);
end
clear tmp