function out=adfgx(text,key,direction,varargin)
% ADFGX Cipher encoder/decoder
% In cryptography, the ADFGX cipher was a field cipher used by the German
% Army on the Western Front during World War I. Invented by Lieutenant Fritz
% Nebel (1891–1977) and introduced in March 1918, the cipher was a
% fractionating transposition cipher which combined a modified Polybius
% square with a single columnar transposition. The cipher is named after
% the six possible letters used in the ciphertext: A, D, F, G and X. The
% letters were chosen deliberately because they are very different from one
% another in the Morse code. That reduced the possibility of operator
% error. Nebel designed the cipher to provide an army on the move with
% encryption that was more convenient than trench codes but was still
% secure. In fact, the Germans believed the ADFGX cipher was unbreakable.
%
% Syntax: 	out=adfgx(text,key,direction,matrix)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the keyword
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%           matrix - a scrambled 5x5 Polybius matrix. If it is empty and
%           direction is 1, the software will generate it. 
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.matrix = the used matrix
%           out.encrypted = the coded text
%
% Examples:
%
% out=adfgx('Hide the gold into the tree stump','leprachaun',1,['BTALP';'DHOZK';'QFVSN';'GICUX';'MREWY'])
%
% out = 
% 
%   struct with fields:
% 
%        matrix: [5×5 char]
%           key: 'leprachaun'
%         plain: 'Hide the gold into the tree stump'
%     encrypted: 'DGFXFFFDDDAAXFGDDADFAXDAAADDDAXXDGFDGGXGDXADFDDFXAADXG'
%
% out=adfgx('DGFXFFFDDDAAXFGDDADFAXDAAADDDAXXDGFDGGXGDXADFDDFXAADXG','leprachaun',-1,['BTALP';'DHOZK';'QFVSN';'GICUX';'MREWY'])
% 
% out = 
% 
%   struct with fields:
% 
%        matrix: [5×5 char]
%           key: 'leprachaun'
%     encrypted: 'DGFXFFFDDDAAXFGDDADFAXDAAADDDAXXDGFDGGXGDXADFDDFXAADXG'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'matrix',[],@(x) isempty(x) | (isequal(size(x),[5,5]) && ischar(x)));
parse(p,text,key,direction,varargin{:});
matrix=p.Results.matrix; clear p

A=65:1:90; A(A==74)=[];
if isempty(matrix) %if there is not a coding matrix
    %if you must decrypt... exit
    assert(direction==1,'This algorithm cannot decode without a matrix')
    %otherwise scramble the A vector and reshape into a 5x5 matrix
    cmatrix=reshape(A(randperm(25)),[5,5]);
    out.matrix=char(cmatrix);
else
    cmatrix=double(upper(matrix));
    %check if the matrix contains all letters except J
    assert(all(ismember(cmatrix(:),A)),'Matrix must use standard English alphabet without J letter. J=I')
    out.matrix=upper(matrix);
end
clear A 
out.key=key;

%ASCII CODES FOR [ABCDEFGHIKLMNOPQRSTUVWXYZ]; 
%change J into I; remove the others
ctext=double(upper(text)); ctext(ctext==74)=73; ctext(ctext<65 | ctext>90)=[];
ckey=double(upper(key)); ckey(ckey==74)=73; ckey(ckey<65 | ckey>90)=[];
%Sort letters in the key
[~,Idx]=sort(ckey);

% as in the example, the secret mixed alphabet is first filled into a 5×5 Polybius square: 
%    A   D   F   G   X
% A  B   T   A   L   P
% D  D   H   O   Z   K
% F  Q   F   V   S   N
% G  G   I   C   U   X
% X  M   R   E   W   Y
switch direction %encrypt
    case 1
    %By using the square, the message is converted to fractionated form: 
    %    a  t  t  a  c  k  a  t  o  n  c  e
    %   AF AD AD AF GF DX AF AD DF FX GF XF
        out.plain=text;
        P={'A' 'D' 'F' 'G' 'X'};
        % Find the index of each characters into Polybius square
        [~,locb]=ismember(ctext,cmatrix);
        % transform index into subscripts
        [I,J]=ind2sub([5,5],locb);
        % transform into ADFGX coding
        tmp=(char(strcat(P(I'),P(J'))))';
        %tmp = AAAAGDAADFGX
        %      FDDFFXFDFXFF
        clear P
        %reshape tmp
        out1=tmp(:)';
        %out1=AFADADAFGFDXAFADDFFXGFXF
        clear locb I J tmp
        %Next, the fractionated message is subject to a columnar
        %transposition. The message is written in rows under a
        %transposition key (here "CARGO"):
        %C A R G O
        %_________
        %A F A D A
        %D A F G F
        %D X A F A
        %D D F F X
        %G F X F 
        %
        %To do this, the length of the message must be a multiple of key
        %length
        L=length(out1); %length of the message
        C=length(ckey); %length of the key (columns)
        R=ceil(L/C); %how many rows we need?
        if L~=C
            tmp=strcat(out1,repmat('Z',1,C*R-L)); %padding
        end
        tmp=reshape(tmp,C,R)';
        %Next, the letters are sorted alphabetically in the transposition
        %key (changing CARGO to ACGOR) by rearranging the columns beneath
        %the letters along with the letters themselves:   
        % A C G O R
        % _________
        % F A D A A
        % A D G F F
        % X D F A A
        % D D F X F
        % F G F   X
        tmp=tmp(:,Idx);
        clear L C R Idx
        %Then, it is read off in columns, in keyword order, which yields
        %the ciphertext.
        tmp=tmp(:)'; 
        %tmp=FAXDFADDDGDGFFFAFAXZAFAFX
        tmp(tmp=='Z')=[]; %eventually remove padding 'Z'
        out.encrypted=tmp; 
        clear tmp
    case -1 %decrypt
        out.encrypted=text;
        %ASCII code for ADFGX
        P=double('ADFGX');
        %check that all letters into encoded text are ADFGX
        assert(all(ismember(ctext,P)))
        L=length(ctext); %length of the message
        C=length(ckey); %length of the key (columns)
        R=ceil(L/C); %how many rows we need?
        N=C*R; %number of the elements of the matrix
        tmp=zeros(R,C); %vector preallocation
        if L<N %we need padding
            padding=C-N+L+1; %starting column to pad
            tmp(R,padding:C)=90; %pad
            %tmp = 0 0 0 0 0
            %      0 0 0 0 0
            %      0 0 0 0 0
            %      0 0 0 0 0
            %      0 0 0 0 90
            for I=1:C %fill the columns into the Idx order
                if Idx(I)<padding %if the column number to fill is not a padded column
                    tmp(:,Idx(I))=ctext(1:R); %fill it
                    ctext(1:R)=[]; %erase the letters that were added
                else
                    tmp(1:R-1,Idx(I))=ctext(1:R-1); %add R-1 letters
                    ctext(1:R-1)=[]; %erase the letters that were added
                end
            end
            clear padding
            %tmp = A F A D A
            %      D A F G F
            %      D X A F A
            %      D D F F X
            %      G F X F Z
        else %we don't need padding
            tmp2=reshape(ctext,R,C); %reshape array into a matrix
            tmp(:,Idx)=tmp2(:,1:C); %back revert the order of the columns
            clear tmp2
        end
        %transform the matrix into a vector
        tmp=tmp'; 
        out1=tmp(:)'; 
        %erase the eventually present pads
        out1(out1==90)=[];
        %out1=AFADADAFGFDXAFADDFFXGFXF
        clear tmp C ctext ckey I Idx L N R
        R=out1(1:2:end); %rows are odds positions of out1
        C=out1(2:2:end); %cols are even positions of out1
        for I=1:5 %convert A=1 D=2 F=3 G=4 X=5
            R(R==P(I))=I;
            C(C==P(I))=I;
        end
        ind=sub2ind([5,5],R,C); %convert subs to index
        out.plain=matrix(ind); %find letters into the matrix
        clear ind R C I
end