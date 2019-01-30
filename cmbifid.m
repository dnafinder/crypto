function out=cmbifid(text,key1,key2,period,direction)
%Conjugated Matrix Bifid Cipher encoder/decoder
%Proceed as for Bifid, but after reading out the numbers horizontally,
%substitute them with the letter found in the second 5x5 Polybius square.
% 
% Syntax: 	out=cmbifid(text,key1,key2,period,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key1 - It is the keyword used to generate the first Polybius Square
%           key2 - It is the keyword used to generate the second Polybius Square
%           period - an integer number used to fractionate the message. It
%           must be less than or equal to message length
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key1 = the used key1
%           out.key2 = the used key2
%           out.period = the used period
%           out.encrypted = the coded text
%
% Examples:
%
% out=cmbifid('Hide the gold into the tree stump','leprachaun','ghosts and goblins',7,1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%        period: 7
%     encrypted: 'QTEVIRAAVYOHOMCOOLYRNLQHRYI'
%
% out=cmbifid('QTEVIRAAVYOHOMCOOLYRNLQHRYI','leprachaun','ghosts and goblins',7,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'QTEVIRAAVYOHOMCOOLYRNLQHRYI'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%        period: 7
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also bifid
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key1',@(x) ischar(x));
addRequired(p,'key2',@(x) ischar(x));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,period,direction);
clear p

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
assert(period<=length(ctext),strcat('Period must be <=',num2str(length(ctext))))
ckey1=double(upper(key1)); ckey1(ckey1>90 | ckey1<65)=[]; 
ckey2=double(upper(key2)); ckey2(ckey2>90 | ckey2<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey1(ckey1==74)=73; 
ckey2(ckey1==74)=73;

switch direction
    case 1 %encrypt
        out.plain=char(ctext);
    case -1 %decript
        out.encrypted=char(ctext);
end
out.key1=char(ckey1);
out.key2=char(ckey2);
out.period=period;

% Polybius square generation from Key1
% For example, the key word is EXTRAORDINARY
% Chars of the key must be choosen only once
ckey1=unique(ckey1,'stable'); %EXTRAODINY
% Add the other letters alphabetically: EXTRAODINYBCFGHKLMPQSUVWZ
A=[65:1:73 75:1:90];
B=[ckey1 A(~ismember(A,ckey1))];
% Rearrange into the square in a clockwise spiral. 
%    1   2   3   4   5
% 1  E   X   T   R   A
% 2  K   L   M   P   O
% 3  H   W   Z   Q   D
% 4  G   V   U   S   I
% 5  F   C   B   Y   N
PS1=B(fliplr(abs(spiral(5)-26)));
clear B ckey1

% Polybius square generation from Key1
% For example, the key word is NOVELTY
% Chars of the key must be choosen only once
ckey2=unique(ckey2,'stable'); %NOVELTY
% Add the other letters alphabetically: NOVELTYABCDFGHIKMPQRSUWXZ
B=[ckey2 A(~ismember(A,ckey2))];
% Rearrange into the square in a snake pattern. 
%    1   2   3   4   5
% 1  N   C   D   R   S
% 2  O   B   F   Q   U
% 3  V   A   G   P   W
% 4  E   Y   H   M   X
% 5  L   T   I   K   Z
PS2=reshape(B,[5,5]); PS2(:,[2 4])=flipud(PS2(:,[2 4]));
clear A B ckey2

switch direction
    case 1 %encrypt
        % Find the index of each characters into Polybius square 1
        [~,locb]=ismember(ctext,PS1);
    case -1 %decrypt
        % Find the index of each characters into Polybius square 2
        [~,locb]=ismember(ctext,PS2);
end
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
        % go to Polybius Square 2
        L=length(A);
        I=A(1:2:L-1); J=A(2:2:L);
        Ind=sub2ind([5,5],I,J); 
        clear A I J L
        out.encrypted=char(PS2(Ind'));
        clear PS* Ind
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
        out.plain=char(PS1(Ind'));
end
