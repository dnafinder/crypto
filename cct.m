function out=cct(text,key,direction)
% COMPLETE COLUMNAR TRASPOSITION Cipher encoder/decoder
% Simple encoder by which the plain text is written into a rectangular
% block by filling each row and taken out by columns in order of the key.
%
% pt=filled block
% key=3 1 2
%
%3 1 2       1 2 3
%f i l       i l f
%l e d       e d l 
%b l o       l o b
%c k x       k x c
% 
%ct=IELK LDOX FLBC.
%
% Syntax: 	out=cct(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the numeric array for trasposition
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Examples:
%
% out=cct('Hide the gold into the tree stump',[3 4 1 2],1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%           key: [3 4 1 2]
%     encrypted: 'DEDOTSPEGITRTXHTONHEUIHLTEEM'
%
% out=cct('DEDOTSPEGITRTXHTONHEUIHLTEEM',[3 4 1 2],-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'DEDOTSPEGITRTXHTONHEUIHLTEEM'
%           key: [3 4 1 2]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it    
    
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'row','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

M=max(key);
[skey,Idx]=sort(key);
assert(isequal(skey,1:1:M),'This key can not be used. Check it!')
clear skey
% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; ctext=char(ctext);
LT=length(ctext);
RL=ceil(LT/M);
if mod(LT,M)~=0
    pad=repmat('X',1,RL*M-LT);
    ctext=reshape([ctext pad],M,RL)';
    clear pad;
else
    switch direction
        case 1 %encrypt
            ctext=reshape(ctext,M,RL)';
        case -1 %decrypt
            ctext=reshape(ctext,RL,M);
    end
end
clear LT

switch direction
    case 1 %encrypt
        out.plain=text;
        out.key=key;
        out.encrypted=reshape(ctext(:,Idx),1,RL*M);
    case -1 %decrypt
        out.encrypted=text;
        out.key=key;
        ctext=reshape(ctext(:,key)',1,RL*M);
        X=find(ctext=='X');
        if ~isempty(X)
            X(X==1)=[]; %If "X" is the first letter, surely it wasn't added;
            c=~ismember(ctext(X-1),'AEIOUY');
            ctext(X(c))=[];
            clear c
        end
        clear X
        out.plain=ctext;
end
clear M RL Idx ctext 