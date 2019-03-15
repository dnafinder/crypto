function out=nihilist2(text,key,direction)
% NIHILIST TRASPOSITION Cipher encoder/decoder
% In the history of cryptography, the Nihilist cipher is a manually
% operated symmetric encryption cipher, originally used by Russian
% Nihilists in the 1880s to organize terrorism against the tsarist regime.
% The term is sometimes extended to several improved algorithms used much
% later for communication by the First Chief Directorate with its spies. 
% A simpler form of the Nihilist was in double transposition.
% The plaintext is arranged into a square. Transpose columns by
% key order and then transpose rows. The ciphertext is taken off by rows.
%
% Syntax: 	out=nihilist2(text,key,direction)
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
% out=nihilist2('Hide the gold into the tree stump',[3 4 6 1 5 2],1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: [3 4 6 1 5 2]
%     encrypted: 'INODT HET  TPUMDETH IE TRSE GLHOE'
%
% out=nihilist2('INODT HET  TPUMDETH IE TRSE GLHOE',[3 4 6 1 5 2],-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'INODT HET  TPUMDETH IE TRSE GLHOE'
%           key: [3 4 6 1 5 2]
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% See also nihilist
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'row','real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

text=upper(text);
M=max(key);
assert(isequal(sort(key),1:1:M),'This key can not be used. Check it!')
LT=length(text);
M2=M^2;
assert(LT<=M2,'With this key you can encrypt a message of %i characthers long.\n Indeed, your message is %i characthers long',M2,LT)

switch direction
    case 1 %encrypt
        if LT<M2
            RL=ceil(LT/M2);
            pad=repmat('§',1,RL*M2-LT);
            ctext=reshape([text pad],M,M)';
            clear RL LT pad M2
        else
            ctext=reshape(text,M,M)';
        end
        clear M
        ctext=ctext(:,key);
        ctext=ctext(key,:);
        ctext=regexprep(reshape(ctext',1,[]),'§','');
        out.plain=text;
        out.key=key;
        out.encrypted=ctext;
    case -1 %decrypt
        if LT<M2
            RL=ceil(LT/M2);
            pad=repmat('§',1,RL*M2-LT);
            clear RL M2
        else
            pad=[];
        end
        clear LT 
        [~,Idx]=sort(key);
        ctext=repmat('^',M,M);
        I=M;
        while ~isempty(pad)
            L=length(pad);
            if L>M
                ctext(Idx(I),:)=repmat('§',1,M);
                pad(1:M)=[];
                I=I-1;
            else
                ctext(Idx(I),Idx(end-L+1:end))=pad;
                pad=[];
            end
        end
        clear I pad L
        tmp2=text;
        for J=1:M
            I=find(ctext(J,:)=='^');
            if ~isempty(I)
                L=length(I);
                ctext(J,I)=tmp2(1:L);
                tmp2(1:L)=[];
            end
        end
        clear I J L tmp2 M
        ctext=ctext(Idx,:);
        ctext=ctext(:,Idx);
        clear Idx
        ctext=regexprep(reshape(ctext',1,[]),'§','');
        out.encrypted=text;
        out.key=key;
        out.plain=ctext;
end
clear ctext