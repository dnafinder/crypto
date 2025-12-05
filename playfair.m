function out=playfair(text,key,direction)
% PLAYFAIR Cipher encoder/decoder
% The Playfair cipher was the first cipher to encrypt pairs of letters in
% cryptologic history. Wheatstone invented the cipher for secrecy in
% telegraphy, but it carries the name of his friend Lord Playfair, first
% Baron Playfair of St. Andrews, who promoted its use. Playfair is no
% longer used by military forces because of the advent of digital
% encryption devices. This cipher is now regarded as insecure for any
% purpose, because modern computers could easily break it within seconds.
% Playfair Cipher is based on a 5x5 Polybius Square with I/J combined.
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax:         out=playfair(text,key,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the keyword (character array or string scalar)
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
% out=playfair('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'NFFLOBPFMEFKBSQMFHSAPWROQBQL'
%
% out=playfair('NFFLOBPFMEFKBSQMFHSAPWROQBQL','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'NFFLOBPFMEFKBSQMFHSAPWROQBQL'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text)
    text = char(text);
end
if isstring(key)
    key = char(key);
end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% ASCII codes for uppercase letters range between 65 and 90
ctext=double(upper(text)); 
ctext(ctext<65 | ctext>90)=[];

ckey=double(upper(key)); 
ckey(ckey>90 | ckey<65)=[];

% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey(ckey==74)=73;

% Chars of the key must be chosen only once
ckey=unique(ckey,'stable');

out.key=char(ckey);

% Polybius square generation from Key
A=[65:1:73 75:1:90];
PS=reshape([ckey A(~ismember(A,ckey))],[5,5])';
clear ckey A

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end

switch direction
    case 1 % Encrypt
        % Break the message into digrams, inserting X (or Q if needed)
        tmp=[];
        while numel(ctext)>1
            a=ctext(1); 
            b=ctext(2);
            if a~=b
                tmp=[tmp a b]; %#ok<*AGROW>
                ctext([1 2])=[];
            else
                if a~=88
                    tmp=[tmp a 88];
                else
                    tmp=[tmp a 81];
                end
                ctext(1)=[];
            end
        end

        if isscalar(ctext)
            if ctext==88
                tmp=[tmp ctext 81];
            else
                tmp=[tmp ctext 88];
            end
        end

        L=numel(tmp)/2;
        ctext=reshape(tmp,2,[])';
        clear a b tmp

    case -1 % Decrypt
        assert(mod(numel(ctext),2)==0,'Ciphertext length must be even after filtering.')
        L=numel(ctext)/2;
        ctext=reshape(ctext,2,[])';
end

tmp=zeros(L,2);

switch direction
    case 1
        A=[2 3 4 5 1];
    case -1
        A=[5 1 2 3 4];
end

for I=1:L
    [R1,C1]=find(PS==ctext(I,1));
    [R2,C2]=find(PS==ctext(I,2));

    if R1~=R2
        if C1~=C2
            tmp(I,:)=[PS(R1,C2) PS(R2,C1)];
        else
            tmp(I,:)=[PS(A(R1),C1) PS(A(R2),C1)];
        end
    else
        tmp(I,:)=[PS(R1,A(C1)) PS(R1,A(C2))];
    end
end

clear PS R1 R2 C1 C2 I ctext A

switch direction
    case 1 % Encrypt
        out.encrypted=char(reshape(tmp',1,[]));
        clear tmp L

    case -1 % Decrypt
        L=L*2;
        tmp=reshape(tmp',1,[]);

        % Find all the "Q"
        Q=find(tmp==81);
        q=[];
        if ~isempty(Q)
            for I=1:numel(Q)
                if Q(I)==L && tmp(Q(I)-1)==88
                    q=[q Q(I)];
                elseif Q(I)>1 && Q(I)<L && tmp(Q(I)-1)==88 && tmp(Q(I)+1)==88
                    q=[q Q(I)];
                end
            end
            clear I
            if ~isempty(q)
                tmp(q)=[];
                L=numel(tmp);
            end
        end
        clear Q q

        % Find all the "X"
        X=find(tmp==88);
        x=[];
        if ~isempty(X)
            for I=1:numel(X)
                if X(I)>1 && X(I)<L
                    if tmp(X(I)-1)==tmp(X(I)+1)
                        x=[x X(I)];
                    end
                end
            end
            clear I
            if ~isempty(x)
                tmp(x)=[];
            end
        end
        clear X x

        out.plain=char(tmp);
        clear tmp L
end
end
