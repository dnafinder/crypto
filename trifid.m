function out=trifid(text,key,period,direction)
% TRIFID Cipher encoder/decoder
%The trifid cipher is a classical cipher invented by Félix Delastelle and
%described in 1902. Extending the principles of Delastelle's earlier
%bifid cipher, it combines the techniques of fractionation and
%transposition to achieve a certain amount of confusion and diffusion: each
%letter of the ciphertext depends on three letters of the plaintext and up
%to three letters of the key.      
%The trifid cipher uses a table to fractionate each plaintext letter into a
%trigram,[2] mixes the constituents of the trigrams, and then applies the
%table in reverse to turn these mixed trigrams into ciphertext letters.
% 
% Syntax: 	out=trifid(text,key1,period,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key1 - It is the keyword used to generate Polybius Square
%           period - an integer number used to fractionate the message. It
%           must be less than or equal to message length
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key1 = the used key1
%           out.period = the used period
%           out.encrypted = the coded text
%
% Examples:
%
% out=trifid('Hide the gold in the tree stump','leprachaun',7,1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%           key: 'LEPRACHAUN'
%        period: 7
%     encrypted: 'AHULQISGGXEQSOPLYRLKISPTJ'
%
% out=trifid('AHULQISGGXEQSOPLYRLKISPTJ','leprachaun',7,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'AHULQISGGXEQSOPLYRLKISPTJ'
%           key: 'LEPRACHAUN'
%        period: 7
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period,direction);

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
assert(period<=length(ctext),strcat('Period must be <=',num2str(length(ctext))))
ckey=double(upper(key)); ckey(ckey>90 | ckey<65)=[]; 

switch direction
    case 1 %encrypt
        out.plain=char(ctext);
    case -1 %decrypt
        out.encrypted=char(ctext);
end
out.key=char(ckey);
out.period=period;

% 3x3x3 Polybius square generation from Key
% For example, the key word is EXTRAORDINARY
% Chars of the key must be choosen only once
ckey=unique(ckey,'stable'); %EXTRAODINY
A=[65:1:90 35]; %Start with a 27-letter alphabet (# as the 27th symbol)
PS=[ckey A(~ismember(A,ckey))]; %EXTRAODINYBCFGHJKLMPQSUVWZ#
clear A ckey
%matrix of coordinates of 3x3x3 PS
C=[1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 3 3 3 3 3 3 3 3 3;...
1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3;...
1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3];

%create a matrix that has 3 rows and an integer multiple of period
L=length(ctext); K=ceil(L/period); tmp=zeros(3,L);
%transform each letter of the text into 3x3x3 PS coordinates
for I=1:L
    tmp(:,I)=C(:,PS==ctext(I));
end
clear I ctext
Y=1; Z=zeros(1,L);
clear L

%take a block of 3 rows and H columns
for I=1:K
    H=min(size(tmp,2),period);
    switch direction
        case 1 %ecrypt
            %reshape reading horizontally
            tmp2=reshape(tmp(:,1:H)',3,H);
        case -1 %decrypt
            %reshape reading vertically
            tmp2=reshape(reshape(tmp(:,1:H),3*H,1),H,3)';
    end
    tmp(:,1:H)=[];
    %return onto 3x3x3 PS
    for J=1:H
        Z(Y)=PS(all(C==tmp2(:,J)));
        Y=Y+1;
    end
end
clear H I J K tmp2 Y

switch direction
    case 1 %ecrypt
        out.encrypted=char(Z);
    case -1 %decrypt
        out.plain=char(Z);
end
clear Z