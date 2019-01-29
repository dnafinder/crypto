function out=bifid(text,key,period,direction)
% BIFID Cipher encoder/decoder
% Bifid is a cipher which combines the Polybius square with transposition,
% and uses fractionation to achieve diffusion. It was invented by Felix
% Delastelle. Delastelle was a Frenchman who invented several ciphers
% including the bifid, trifid, and four-square ciphers. The first
% presentation of the bifid appeared in the French Revue du Génie civil in
% 1895 under the name of cryptographie nouvelle. It has never been used by
% a military or government organisation, only ever by amateur
% cryptographers. 
% 
% Syntax: 	out=bifid(text,key1,period,direction)
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
% out=bifid('Hide the gold into the tree stump','leprachaun',7,1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%        period: 7
%     encrypted: 'TGZAPSFFAUKMKBQKKEUSXETMSUP'
%
% out=bifid('TGZAPSFFAUKMKBQKKEUSXETMSUP','leprachaun',7,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'TGZAPSFFAUKMKBQKKEUSXETMSUP'
%           key: 'LEPRACHAUN'
%        period: 7
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgx, adfgvx, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period,direction);
clear p

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
assert(period<=length(ctext),strcat('Period must be <=',num2str(length(ctext))))
ckey=double(upper(key)); ckey(ckey>90 | ckey<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey(ckey==74)=73; 

switch direction
    case 1 %encrypt
        out.plain=char(ctext);
    case -1 %decript
        out.encrypted=char(ctext);
end
out.key=char(ckey);
out.period=period;

% Polybius square generation from Key
% For example, the key word is EXTRAORDINARY
% Chars of the key must be choosen only once
ckey=unique(ckey,'stable'); %EXTRAODINY
% Add the other letters alphabetically: EXTRAODINYBCFGHKLMPQSUVWZ
A=[65:1:73 75:1:90];
B=[ckey A(~ismember(A,ckey))];
% Rearrange into the square in a clockwise spiral. 
%    1   2   3   4   5
% 1  E   X   T   R   A
% 2  K   L   M   P   O
% 3  H   W   Z   Q   D
% 4  G   V   U   S   I
% 5  F   C   B   Y   N
PS=B(fliplr(abs(spiral(5)-26)));
clear A B ckey

% Find the index of each characters into Polybius square
[~,locb]=ismember(ctext,PS);
clear ctext
% transform index into subscripts
[I,J]=ind2sub([5,5],locb);
clear locb
% If it is needed, pad I and J with 0 to ensure that their lengths
% are multiple of period
K=length(I);
L=ceil(K/period);
pad=zeros(1,L*period-K);
clear K
if ~isempty(pad)
    I=[I pad]; J=[J pad];
end

switch direction
    case 1 %encrypt
        % reshape and join them according to period
        I=reshape(I,period,L)'; J=reshape(J,period,L)';
        A=[I J]'; A=A(:);
        % erase 0 if it is needed
        if ~isempty(pad)
            A(A==0)=[];
        end
        clear pad
        % return onto Polybius Square
        L=length(A);
        I=A(1:2:L-1); J=A(2:2:L);
        Ind=sub2ind([5,5],I,J); 
        clear A I J L
        out.encrypted=char(PS(Ind'));
        clear PS Ind
    case -1 %decrypt
        % reshape and join them according to period
        I=reshape(I,period,L); J=reshape(J,period,L); clear L
        A=[I(:) J(:)];
        b=length(A)/period; %blocks
        I=zeros(b*period,1); J=I;
        for K=1:b-1
            z=period*K;
            B=A(z-period+1:z,1:2)'; B=B(:);
            I(z-period+1:z)=B(1:period);
            J(z-period+1:z)=B(period+1:end);
        end
        clear K b B
        A(1:z,:)=[]; A=A'; A=A(:);
        if ~isempty(pad)
            lp=period-length(pad);
        else
            lp=period;
        end
        I(z+1:z+lp)=A(1:lp); A(1:lp)=[];
        J(z+1:z+lp)=A(1:lp);
        clear A z lp
        if ~isempty(pad)
            I(I==0)=[];
            J(J==0)=[];
        end
        clear pad
        Ind=sub2ind([5,5],I,J); 
        clear I J
        out.plain=char(PS(Ind'));
end
