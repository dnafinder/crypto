function out=railfence(text,key,direction)
% RAIL FENCE Cipher encoder/decoder
% The rail fence cipher (also called a zigzag cipher) is a form of
% transposition cipher. It derives its name from the way in which it is
% encoded. In the rail fence cipher, the plain text is written downwards
% and diagonally on successive "rails" of an imaginary fence, then moving
% up when we reach the bottom rail. When we reach the top rail, the message
% is written downwards again until the whole plaintext is written out. The
% message is then read off in rows.    
% For example, if we have 3 "rails" and a message of 'WE ARE DISCOVERED
% FLEE AT ONCE', the cipherer writes out (erase the spaces for semplicity): 
%
% W . . . E . . . C . . . R . . . L . . . T . . . E
% . E . R . D . S . O . E . E . F . E . A . O . C .
% . . A . . . I . . . V . . . D . . . E . . . N . .
%
% Then reads off to get the ciphertext: WECRLTEERDSOEEFEAOCAIVDEN
%
% Syntax: 	out=railfence(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the number od rails
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
% out=railfence('Hide the gold into the tree stump',3,1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: 3
%     encrypted: 'H  DTHRSPIETEGL NOTETE TMDHOI  EU'
%
% out=railfence('H  DTHRSPIETEGL NOTETE TMDHOI  EU',3,-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'H  DTHRSPIETEGL NOTETE TMDHOI  EU'
%           key: 3
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

text=upper(text);

% For example, we use again the messagge 'WE ARE DISCOVERED FLEE AT ONCE'
% (without spaces) and 3 rails. The rails will be the rows of a sparse
% matrix. 

%           B1      B2       B3       B4       B5       B6       B7
% row 1 |X . . . |X . . . |X . . . |X . . .| X . . . |X . . . |X . . . |
% row 2 |. X . X |. X . X |. X . X |. X . X| . X . X |. X . X |. X . X |
% row 3 |. . X . |. . X . |. . X . |. . X .| . . X . |. . X . |. . X . |
% cols   1 2 3 4  5 6 7 8  9 1 1 1  1 1 1 1  1 1 1 2  2 2 2 2  2 2 2 2
%                            0 1 2  3 4 5 6  7 8 9 0  1 2 3 4  5 6 7 8

% The zig-zag pattern shows a repeated motif for the rows: 1 2 3 2
% Construct the repeated motif (phase)
tmp=1:1:key;
phase=[tmp fliplr(tmp(2:end-1))];
clear tmp 

%How many "blocks" of repeated phase are needed? 
L=length(text);
LP=length(phase);
B=ceil(L/LP);
%repeat the phase B times
rows=repmat(phase,1,B);
%how many columns are needed?
N=B*LP;
cols=1:1:N;
clear phase B LP 
%preallocate a key x N matrix
matrix=NaN(key,N);
%Transform subscripts to index
Ind=sub2ind([key,N],rows,cols);

switch direction
    case 1 %encrypt
        out.plain=text;
        out.key=key;
        %Transform subscripts to index
        Ind=sub2ind([key,N],rows,cols);
        %Fill the matrix with the ASCII codes of the text
        matrix(Ind(1:L))=double(text);
        clear Ind L rows cols
        %Reshape the matrix and then reads off to get the ciphertext
        matrix=reshape(matrix',1,[]);
        %squeeze out NaNs
        matrix(isnan(matrix))=[];
        %transform back the ASCII codes
        out.encrypted=char(matrix);
    case -1 %decrypt
        out.encrypted=text;
        out.key=key;
%           B1      B2       B3       B4       B5       B6       B7
% row 1 |1 . . . |1 . . . |1 . . . |1 . . .| 1 . . . |1 . . . |1 . . . |
% row 2 |. 2 . 2 |. 2 . 2 |. 2 . 2 |. 2 . 2| . 2 . 2 |. 2 . 2 |. 2 . 2 |
% row 3 |. . 3 . |. . 3 . |. . 3 . |. . 3 .| . . 3 . |. . 3 . |. . 3 . |
% cols   1 2 3 4  5 6 7 8  9 1 1 1  1 1 1 1  1 1 1 2  2 2 2 2  2 2 2 2
%                            0 1 2  3 4 5 6  7 8 9 0  1 2 3 4  5 6 7 8
        matrix(Ind)=rows;
        %Erase unneeded columns
        if L<N
            matrix(:,L+1:end)=[];
        end
        clear L rows cols
        %convert text into ASCII codes
        ctext=double(text);              
        for I=1:1:key
            %Find the position of I=1,2...key
            Idx=matrix==I;
            %how many 1,2...key?
            S=sum(Idx(:));
            %substitute I with the S-length portion of the coded text
            matrix(Idx)=ctext(1:S);
            %shorten the coded text
            ctext(1:S)=[];
        end
        %Trasform the matrix into a column vector and squeeze out NaNs
        matrix=matrix(:);  
        matrix(isnan(matrix))=[]; 
        out.plain=char(matrix');
end