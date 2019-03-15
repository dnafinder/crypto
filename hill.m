function out=hill(text,key,direction)
% HILL Cipher encoder/decoder
% In classical cryptography, the Hill's cipher is a polygraphic substitution
% cipher based on linear algebra. Invented by Lester S. Hill in 1929, it was
% the first polygraphic cipher in which it was practical (though barely) to
% operate on more than three symbols at once. The following discussion
% assumes an elementary knowledge of matrices.     
% Each letter is represented by a number modulo 26. Often the simple scheme
% A = 0, B = 1, ..., Z = 25 is used, but this is not an essential feature of
% the cipher. To encrypt a message, each block of N letters (considered as
% an N-component vector) is multiplied by cipher matrix, a NxN matrix, 
% against modulus 26.
% The cipher key should be chosen randomly from the set of invertible NxN
% matrices (modulo 26).   
% In order to decrypt, we turn the ciphertext back into a vector, then
% simply multiply by the MODULAR inverse matrix of the cipher matrix.
% There are two complications that exist in picking the encrypting matrix.
% Not all matrices have an inverse. The matrix will have an inverse if and
% only if its determinant is not zero. Moreover, in the case of the Hill's
% Cipher, the determinant of the encrypting matrix must not have any common
% factors with the modular base. Thus, if we work modulo 26 as above, the
% determinant must be nonzero, and must not be divisible by 2 or 13. If the
% determinant is 0, or has common factors with the modular base, then the
% matrix cannot be used in the Hill's cipher, and another matrix must be
% chosen (otherwise it will not be possible to decrypt).   
% The risk of the determinant having common factors with the modulus can be
% eliminated by making the modulus prime. Consequently, a useful variant of
% the Hill's cipher adds 3 extra symbols (such as a space, a period and a
% question mark) to increase the modulus to 29 or 41 (including numbers,
% space, point, coma, question mark and tract).     
% We will use a 41 characthers map.
% When operating on 2 symbols at once, a Hill cipher offers no particular
% advantage over Playfair or the bifid cipher, and in fact is weaker than
% either, and slightly more laborious to operate by pencil-and-paper. As
% the dimension increases, the cipher rapidly becomes infeasible for a
% human to operate by hand.     
%
% Syntax: 	out=hill(text,key,direction)
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
% out=hill('Hide the gold into the tree stump','leprachaun',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%           key: 'leprachaun'
%     encrypted: 'WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA'
%
% out=hill('WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA','leprachaun',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA'
%           key: 'leprachaun'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
clear p

%mapping array
map=[double(upper(' abcdefghijklmnopqrstuvwxyz0123456789.?,-'));0:1:40];
%map the key
[~,idx]=ismember(double(upper(key)),map(1,:));
ckey=map(2,idx);
clear idx
%arrange ckey into a square matrix
LK=length(ckey);
N=ceil(sqrt(LK));
SLK=N^2;
if SLK>LK
    % Repeat the key since having a square number lenght
    RLK=ceil(SLK/LK); 
    key2=repmat(ckey,1,RLK); ckey=key2(1:SLK);
    clear RLK key2
end
clear LK
% reshape it into a square matrix
K=reshape(ckey,N,N)';
clear ckey 
%check if matrix is invertible
D=round(det(K));
assert(D~=0,'The key matrix is not invertible. You will never decode.')
%check if determinant of the matrix is divisible by 41
[f,r,~] = gcd(mod(D,41),41);
assert(f~=41,'The key matrix determinat is divisible by 41. You will never decode.')
clear f
%map the text
[~,idx]=ismember(double(upper(text)),map(1,:));
ctext=map(2,idx);
clear idx
%check if messagge must be padded with 0: lenght must be multiple
%of number of elements of encrypting matrix
LT=length(ctext);
Z=ceil(LT/SLK);
pad=zeros(1,Z*SLK-LT);
if ~isempty(pad)
    ctext=[ctext pad];
    LT=LT+length(pad);
end
clear pad Z SLK

switch direction
    case 1 %encrypt
        clear D r
        %reshape text: text matrix rows must be equal to encryptyng matrix columns
        T=reshape(ctext,N,LT/N)';
        clear ctext N LT
        E=mod(T*K,41)'; %encrypt
        clear K T
        %back mapping
        [~,idx]=ismember(reshape(E,[],1)',map(2,:));
        clear E
        out.plain=text;
        out.key=key;
        out.encrypted=deblank(char(map(1,idx)));
    case -1 %decrypt
        %reshape text: text matrix rows must be equal to encryptyng matrix columns
        T=reshape(ctext',N,LT/N)';
        clear ctext N LT
        %MODULAR inverse matrix of the cipher matrix
        IK=mod(round(inv(K)*D*r),41); %#ok<MINV>
        clear K D r
        P=mod(T*IK,41)'; %decrypt
        clear IK T
        %back mapping
        [~,idx]=ismember(reshape(P,[],1)',map(2,:));
        clear P 
        out.encrypted=text;
        out.key=key;
        out.plain=deblank(char(map(1,idx)));
end
clear map idx