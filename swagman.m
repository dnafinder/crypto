function out=swagman(text,direction,varargin)
%SWAGMAN Cipher encoder/decoder
%The Swagman is a trasposition cipher that use a Latin Square. 
%In combinatorics and in experimental design, a Latin square is an n × n
%matrix filled with n different symbols, each occurring exactly once in each
%row and exactly once in each column. An example of a 3x3 Latin square is:
%A B C 
%C A B
%B C A
%
% Syntax: 	out=swagman(text,direction,LS)
%
%     Input:
%           text - It is a characters array to encode or decode
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%           LS - it is the Latin square. If it is empty and direction is 1,
%           the software will generate it. It is mandatory to decrypt.
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
%           out.LS = the used Latin Square
%           out.encrypted = the coded text
%
% Examples:
% LS=[1 4 5 3 2; 3 1 2 5 4; 4 2 3 1 5; 5 3 4 2 1; 2 5 1 4 3];
% out=swagman('Hide the gold into the tree stump',1,LS)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%            LS: [5×5 double]
%     encrypted: 'HUENTGTRIMPOOEDTEELSTDHHIET'
%
% out=swagman('HUENTGTRIMPOOEDTEELSTDHHIET',-1,LS)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'HUENTGTRIMPOOEDTEELSTDHHIET'
%            LS: [5×5 double]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'LS',[], @(x) validateattributes(x,{'numeric'},{'2d','real','finite','nonnan','nonempty','integer','positive','square'}));
parse(p,text,direction,varargin{:});
LS=p.Results.LS;
clear p varargin

switch direction
    case 1 %encrypt
        if ~isempty(LS) %check if LS is a Latin Square
            n=islatin(LS); 
        else %create a Latin Square
            n=floor(4*(1 + rand(1))); %choose N rows between 4 and 8
            LS=toeplitz([1,n:-1:2],1:n);
            LS=LS(randperm(n),randperm(n));
        end
        out.plain=text;
    case -1 %decrypt
        assert(~isempty(LS),'The algorithm can not decrypt without the used matrix')
        n=islatin(LS); %check if LS is a Latin Square
        out.encrypted=text;
end
out.LS=LS;

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[];
%length of the text
LT=length(ctext);
%number of columns
c=ceil(LT/n);
%spaces needed to fill the rectangle
pad=n*c-LT;
clear LT
%index of the sorted latin square
[~,Idx]=sort(LS);

switch direction
    case 1 %encrypt
        %rearrange the text horizontally into a nxc matrix
        tmp=char(reshape([ctext repmat(32,1,pad)],c,n)');
        clear ctext
        %the modular function is used to correctly choose the latin square
        %column to use for the trasposition
        for I=1:c
            cc=mod(I-1,n)+1; %choosed column
            tmp(:,I)=tmp(Idx(:,cc),I);%perform trasposition
        end
        clear Idx I c cc n
        %reshape into a vector reading vertically
        tmp=reshape(tmp,1,[]);
        %remove spaces
        tmp(tmp==32)=[];
        out.encrypted=char(tmp);
        clear tmp
    case -1 %decrypt
        if pad==0 %if we don't need padding
            %simply reshape the vector into a nxc matrix
            tmp=char(reshape(ctext,n,c));
        else
            K=c-pad; %complete columns
            z=K*n; %elements
            tmp=zeros(n,c); %matrix preallocation
            tmp(:,1:K)=reshape(ctext(1:z),n,K); %start to fill the full columns
            ctext(1:z)=[]; %erase used characters
            z=1;
            for J=1:pad %J-th column
                for I=1:n %I-th row
                    %the modular function is used to correctly choose the
                    %latin square column (in this case in the index)
                    cc=mod(J+K-1,n)+1;
                    if Idx(I,cc)==n %if it is the highest element add the pad
                        tmp(I,J+K)=32;
                    else %add a character
                        tmp(I,J+K)=ctext(z);
                        z=z+1;
                    end
                end
            end
        end
        clear ctext I J K z Idx
        tmp=char(tmp);
        for I=1:c
            %the modular function is used to correctly choose the latin square
            %column to use for the trasposition
            cc=mod(I-1,n)+1;
            tmp(:,I)=tmp(LS(:,cc),I);
        end
        clear I cc c n
        %reshape into a vector reading vertically
        tmp=reshape(tmp',1,[]);
        %remove spaces
        out.plain=tmp(1:end-pad);
        clear tmp
end
end

function r=islatin(x)
[r,c]=size(x);
assert(r==c,'LS must be a square matrix!')
ca=1:1:r;
for I=1:r
    u=unique(x(I,:));
    assert(length(u)==r && all(ismember(u,ca)),'This is not a Latin square')
end
for I=1:c
    u=unique(x(:,I));
    assert(length(u)==c && all(ismember(u,ca)),'This is not a Latin square')
end
clear c ca I u
end