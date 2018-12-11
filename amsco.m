function out=amsco(text,key,direction)
% AMSCO Cipher encoder/decoder
% This algorithm arranges the plain text into a matrix, alternating digraphs
% and single letter. The number of columns is given by the max number of
% the key. Then, the columns are rearrangend using the key and the text is
% read vertically.
%
% Syntax: 	out=amsco(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is a characters array of the digits used as key.
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
% out=amsco('Hide the gold in the tree stump','3142',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'Hide the gold in the tree stump'
%           key: '3142'
%     encrypted: 'DOHSHIRMHIEGNTEEPETLDETTU'
%
% out=amsco('DOHSHIRMHIEGNTEEPETLDETTU','3142',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'DOHSHIRMHIEGNTEEPETLDETTU'
%           key: '3142'
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; ctext=char(ctext);
% Convert key into a vector
K=double(key)-48;
LK=length(K); %how many columns?
[~,Idx]=sort(K); %take the index of the ordered columns
clear K

switch direction
    case 1 %encrypt
        out.plain=text;
        out.key=key;
        % example:
        % text='Incomplete columnar with alternating single letters and digraphs';
        % key='41325';
        % ctext='INCOMPLETECOLUMNARWITHALTERNATINGSINGLELETTERSANDDIGRAPHS'
        
        % check if lenght of text is multiple of 3; if not, pad the text with '*'
        M=mod(length(ctext),3);
        if M~=0
            ctext=[ctext repmat('*',1,3-M)];
        end
        clear M
        LT2=length(ctext); LT1=LT2/3; LT2=LT2*4/3; clear LT
        % Reshape ctext into a Nx3 matrix; add a fourth column of '*' and back
        % reshape into a single line
        % A=INC*OMP*LET*ECO*LUM*NAR*WIT*HAL*TER*NAT*ING*SIN*GLE*LET*TER*SAN*DDI*GRA*PHS*
        A=reshape([reshape(ctext,3,LT1)' repmat('*',LT1,1)]',1,LT2);
        clear LT1 ctext
        
        % check if lenght of A is multiple of key length; if not, pad the text with '*'
        LK=LK*2;
        M=mod(LT2,LK);
        Z=LK-M;
        if M~=0
            LT2=LT2+Z;
            A=[A repmat('*',1,Z)];
            clear Z
        end
        clear M
        % reshape A into NxLK*2 columns
        % B =
        % IN|C*|OM|P*|LE
        % T*|EC|O*|LU|M*
        % NA|R*|WI|T*|HA
        % L*|TE|R*|NA|T*
        % IN|G*|SI|N*|GL
        % E*|LE|T*|TE|R*
        % SA|N*|DD|I*|GR
        % A*|PH|S*|**|**
        %  4| 1| 3| 2| 5
        B=reshape(A,LK,LT2/LK)';
        clear A
        
        % Reorder columns using the key
        % C=
        % C*|P*|OM|IN|LE
        % EC|LU|O*|T*|M*
        % R*|T*|WI|NA|HA
        % TE|NA|R*|L*|T*
        % G*|N*|SI|IN|GL
        % LE|TE|T*|E*|R*
        % N*|I*|DD|SA|GR
        % PH|**|S*|A*|**
        % 1 | 2| 3| 4| 5
        I=1:2:LK;
        I=I(Idx);
        clear Idx
        C=B(:,reshape([I;I+1],1,LK));
        clear B Idx I
        
        % Reshape C into a 2xZ matrix
        % D =
        % CERTGLNPPLTNNTI*OOWRSTDSITNLIESALMHTGRG*
        % *C*E*E*H*U*A*E**M*I*I*D*N*A*N*A*E*A*L*R*
        I=LT2/LK; Z=LT2/2;
        fine=I:I:Z;
        inizio=fine-I+1;
        D=repmat('*',2,Z); %matrix preallocation
        clear I Z
        I=1;
        C=C';
        for Z=1:2:LK
            D(:,inizio(I):fine(I))=C(Z:Z+1,:);
            I=I+1;
        end
        clear I Z LK C inizio fine
        
        % Back reshape D into a single line
        % E=C*ECR*TEG*LEN*PHP*LUT*NAN*TEI***OMO*WIR*SIT*DDS*INT*NAL*INE*SAA*LEM*HAT*GLR*GR**
        E=reshape(D,1,LT2);
        clear LT2 D
        % Erase '*'
        E(E=='*')=[];
        out.encrypted=E;
        clear E
    case -1 %decrypt
        out.encrypted=text;
        out.key=key;
        LK2=LK*2;
        LT=length(ctext);
        asterisks=floor(LT/3); %number of * for single letters 
        LT=LT+asterisks;
        clear asterisks;
        R=ceil(LT/LK2); %rows
        M=floor((R*LK2-LT)/2); %is the matrix padded?
        %the extrapad is an * that is inserted instead of a digraph
        extrapad=R*LK2-LT-M*2;
        if M~=0
            padded=LK:-1:LK-M+1; %padded columns
            clear Z
        else
            padded=[];
        end
        clear M LT
        B=repmat('*',R,LK2); %Matrix preallocation
        % Reorder columns using the key
        I=1:2:LK2;
        I=I(Idx);
        S=1; F=mod(LK,2);
        for J=1:LK
            H=ismember(Idx(J),padded);
            switch mod(Idx(J),2)
                case 0 %we must fill a column that start with single letter
                    B(1,I(J))=ctext(S);
                    S=S+1;
                    lr=R-H;
                    for X=2:lr
                        switch F
                            case 0 %If columns are even continue with single
                                B(X,I(J))=ctext(S);
                                S=S+1;
                            case 1 %If columns are even alternate single and digraph
                                switch mod(X,2)
                                    case 0
                                        %check if you need to introduce the extrapad
                                        if X==lr && extrapad~=0 && I(J)==min(padded)*2-3
                                            B(X,I(J))=ctext(S);
                                            S=S+1;
                                        else
                                            B(X,I(J):I(J)+1)=ctext(S:S+1);
                                            S=S+2;
                                        end
                                    case 1
                                        B(X,I(J))=ctext(S);
                                        S=S+1;
                                end
                        end
                    end
                case 1 %we must fill a column that start with digraph
                    B(1,I(J):I(J)+1)=ctext(S:S+1);
                    S=S+2;
                    lr=R-H;
                    for X=2:lr
                        switch F
                            case 0 %If columns are even continue with digraph
                                %check if you need to introduce the extrapad
                                if X==lr && extrapad~=0 && I(J)==min(padded)*2-3
                                    B(X,I(J))=ctext(S);
                                    S=S+1;
                                else
                                    B(X,I(J):I(J)+1)=ctext(S:S+1);
                                    S=S+2;
                                end
                            case 1 %If columns are even alternate single and digraph
                                switch mod(X,2)
                                    case 0
                                        B(X,I(J))=ctext(S);
                                        S=S+1;
                                    case 1
                                        %check if you need to introduce the extrapad
                                        if X==lr && extrapad~=0 && I(J)==min(padded)*2-3
                                            B(X,I(J))=ctext(S);
                                            S=S+1;
                                        else
                                            B(X,I(J):I(J)+1)=ctext(S:S+1);
                                            S=S+2;
                                        end
                                end
                        end
                    end
            end
        end
        clear S X H I J Idx padded ctext extrapad F LK lr
        %back reshape into a vector
        B=reshape(B',1,R*LK2);
        % Erase '*'
        B(B=='*')=[];
        out.plain=B;
        clear B R LK2
end


