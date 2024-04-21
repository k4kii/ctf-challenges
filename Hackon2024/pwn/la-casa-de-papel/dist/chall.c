#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef enum { false, true } bool;
typedef enum {small, medium, large } note_sz;

#define MAX_NOTES 4
#define TAM_TEXT 0x410
#define TAM_FOOTER 0x18

typedef struct t_note{
    char* text;
    char* footer;
    bool is_freed;
    bool is_written;
    bool has_been_edited_text;
    bool has_been_edited_footer;
    bool has_been_edited_header;
    note_sz size;
} Note, *pNote;

Note notes[MAX_NOTES]; 

void
init();

void
banner();

void
show_options();

int
read_int();

void
read_text_input(char* dst, int nbytes);

int
available_notes_create();
int
available_notes_throw();

void
create_note();

void
read_note();

void
edit_note();

void
throw_note();

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    banner();

    while(true){
        show_options();
        int op = read_int();
        switch (op){
            case 0:
                create_note();
                continue;
            case 1:
                edit_note();
                continue;
            case 2:
                read_note();
                continue;
            case 3:
                throw_note();
                continue;

            case 4:
                break;

            default:
                puts("Invalid option! Try again!");
                continue;
        }

        break;
    }

    puts("Good bye!!");

    fflush(stderr);
    fflush(stdout);
    fflush(stdin);
}

void
banner(){
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡒⠦⠤⠤⠄⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⢼⠀⠀⠒⠒⠤⠤⠤⠤⠤⣀⣀⣀⣀⠀⠀⠘⡇⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⢀⣀⠤⠔⠒⠉⠁⢀⣼⡀⠀⢠⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡧⠚⠉⢹⡀⠀⠀⠀⠀⠀⠀");
    puts("⠰⣖⠊⠉⠀⠀⠀⣠⠔⠚⠉⠁⢀⡇⠀⡀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⢀⡇⠀⣤⠀⢷⡀⠀⠀⠀⠀⠀");
    puts("⠀⠈⠳⡄⠀⠀⠋⣠⠖⠂⡠⠖⢙⡇⠀⠈⠉⠉⠉⠉⠓⠒⠒⠒⠒⠒⠆⠀⠀⣷⡀⠉⢦⠀⢳⡀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠈⢦⠀⠀⠁⠀⠀⠀⢀⠼⡇⠀⠀⠦⠤⠤⠄⡀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠱⡀⠀⠳⡀⠙⣆⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠳⡄⠀⢀⡤⠊⠁⢠⡇⠀⠠⠤⢤⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⡧⡀⠙⢄⠀⠱⠄⠈⠳⡄⠀");
    puts("⠀⠀⠀⠀⠀⠀⠙⡄⠀⠀⡠⠔⢻⠀⠀⠀⠀⠀⠀⠠⣄⣀⣀⣁⣀⠀⠀⠀⠀⡇⠱⡀⠀⠀⠀⠀⠀⣀⣘⣦");
    puts("⠀⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⡸⠀⠀⠰⣄⣀⡀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⡇⠀⠃⢀⣠⠴⠛⠉⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠘⡄⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠙⠒⠀⠀⠀⠠⡇⣠⠔⠋⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡄⢸⠁⠀⠀⠀⠒⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⢰⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠉⠑⠢⣄⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣎⣀⠀⠀⠀⠀⠀⠀⠀⠢⠤⣀⠀⠀⠁⠀⠀⠀⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢡⠉⠙⠒⠤⢤⡀⠀⠀⠀⠀⠉⠒⠀⠀⠀⠀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠶⠒⠊⠉⠉⠉⠓⠦⣀⠀⠀⠀⠀⠀⠀⢰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠲⢄⡀⠀⠀⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠲⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀");

}

void
show_options(){
    puts("\nWhat would you like to do?");
    puts("[0] Create new note.");
    puts("[1] Edit existing note.");
    puts("[2] Read existing note.");
    puts("[3] Throw note to the bin.");
    puts("[4] Exit.");
}

void
init () {
    for(int i = 0; i < MAX_NOTES; i++){
        notes[i].text = NULL;    
        notes[i].footer = NULL;    
        notes[i].is_freed = false;
        notes[i].is_written = false;
        notes[i].has_been_edited_text = false;
        notes[i].has_been_edited_footer = false;
        notes[i].has_been_edited_header = false;
    }
}

int
read_int(){
    int in;
    putchar('>');
    scanf("%d", &in);
    return in;
}

void
read_text_input(char* dst, int nbytes){
    putchar('>');
    read(0, dst, nbytes);
}

int
available_notes_create(){
    int count = 0;
    for(int i = 0; i < MAX_NOTES; i++){
        if(!notes[i].is_written){
            count++;
        }
    }
    return count;
}

int
available_notes_throw(){
    int count = 0;
    for(int i = 0; i < MAX_NOTES; i++){
        if(!notes[i].is_freed){
            count++;
        }
    }
    return count;
}

void
print_note_idxs(){
    printf("[ ");
    for(int i = 0; i < MAX_NOTES; i++){
        printf("%d ", i);
    }
    puts("]");
}

void
clean_whitespaces(char *src){
    char *aux = src;
    while(*aux != '\0'){
        aux++;
        if(*aux == ' ') *aux = '_';
    }
}

int
fill_fields(int idx, bool with_footer){
    int text_offset = 0;

    puts("Enter the author's name:");
    read_text_input(notes[idx].text + text_offset, 0x8);
    clean_whitespaces(notes[idx].text + text_offset);

    if(with_footer){
        strncpy(notes[idx].footer + text_offset, notes[idx].text + text_offset, 0x8);
    }

    text_offset += 0x8;
    puts("Enter the author's surname:");
    read_text_input(notes[idx].text+text_offset, 0x8);
    clean_whitespaces(notes[idx].text+text_offset);

    if(with_footer){
        strncpy(notes[idx].footer + text_offset, notes[idx].text + text_offset, 0x8);
    }

    text_offset += 0x8;
    puts("Enter the date:");
    read_text_input(notes[idx].text+text_offset, 0x8);
    clean_whitespaces(notes[idx].text+text_offset);

    if(with_footer){
        strncpy(notes[idx].footer + text_offset, notes[idx].text + text_offset, 0x8);
    }

    text_offset += 0x8;
    puts("Enter the city:");
    read_text_input(notes[idx].text + text_offset, 0x8);
    clean_whitespaces(notes[idx].text + text_offset);

    text_offset += 0x8;
    return text_offset;
}

void
print_footer(char *src){
    printf("Name: %s\n", src);
    printf("Surname: %s\n", src + 0x8);
    printf("Date: %s\n", src + 0x10);
}

void
print_header(char *src){
    print_footer(src);
    printf("City: %s\n", src + 0x18);
}

void
throw_note(){
    int idx;
    while(true){
        int available = available_notes_throw();
        if (!available){
            puts("There are no more pages left to tear bro\n");
            return;
        }

        puts("What is the index of the note you want to throw to the bin?");
        print_note_idxs();

        idx = read_int();
        if ((idx < 0 || idx >= MAX_NOTES) || notes[idx].is_freed || notes[idx].text == NULL ){
            puts("Invalid note!!");
            continue;
        }
        break;
    }

    notes[idx].is_freed = true;
    free(notes[idx].text);
    puts("3-pointer in the bin!!");
}

void
read_note(){
    int idx;
    while(true){
        puts("What is the index of the note you want to read?");
        print_note_idxs();

        idx = read_int();
        if ((idx < 0 || idx >= MAX_NOTES) || notes[idx].text == NULL ){
            puts("Invalid note!!");
            continue;
        }
        break;
    }

    printf("Note [%d]\n", idx);
    puts("Header");
    puts("-----------------------------");
    print_header(notes[idx].text);
    puts("-----------------------------");
    puts("");

    if(!notes[idx].is_freed){
        printf("Text: %s\n", notes[idx].text + 0x20);
    }else{
        puts("Text: --DELETED--");
    }

    puts("");
    if(notes[idx].footer != NULL){
        puts("Footer");
        puts("-------------------------------");
        print_footer(notes[idx].footer);
    }
}

void
edit_note(){
    int idx;
    while(true){
        puts("What is the index of the note you want to edit?");
        print_note_idxs();
        
        idx = read_int();
        if ((idx < 0 || idx >= MAX_NOTES) || !notes[idx].is_written || notes[idx].text == NULL){
            puts("Invalid note!!");
            continue;
        }

        break;
    }

    int edit_footer;
    while(true){
        puts("Do you want to edit the text a footer field or a header field? [text: 0, footer: 1, header: 2]");
        edit_footer = read_int();
        if(edit_footer < 0 || edit_footer > 2){
            puts("Invalid choize!!");
            continue;
        }
        if(!edit_footer && notes[idx].has_been_edited_text){
            puts("The text has already been edited. You don't have any tipex left!");
            return;
        }
        if(edit_footer == 1 && notes[idx].has_been_edited_footer){
            puts("The footer has already been edited. You don't have any tipex left!");
            return;
        }
        if(edit_footer == 2 && notes[idx].has_been_edited_header){
            puts("The header has already been edited. You don't have any tipex left!");
            return;
        }

        break;
    }

    if(edit_footer == 1){
        int field;
        while(true){
            puts("What field have you messed up? [Name: 0, Surname: 1, Date: 2]");        
            field = read_int();
            if(field < 0 || field > 2){
                puts("That field doesn't exist!!");
                continue;
            }
            break;
        }

        notes[idx].has_been_edited_footer = true;

        int offset = field * 0x8;
        char *buf = notes[idx].footer + offset;

        puts("Enter the new field value");
        read_text_input(buf, 0x8);
        clean_whitespaces(buf);

    }else if (edit_footer == 2){
        int field;
        while(true){
            puts("What field have you messed up? [Name: 0, Surname: 1, Date: 2, City: 3]");        
            field = read_int();
            if(field < 0 || field > 3){
                puts("That field doesn't exist!!");
                continue;
            }
            break;
        }

        notes[idx].has_been_edited_header = true;

        int offset = field * 0x8;
        char *buf = notes[idx].text + offset;

        puts("Enter the new field value");
        read_text_input(buf, 0x8);
        clean_whitespaces(buf);

    }else{
        notes[idx].has_been_edited_text = true;

        int header_sz = 0x20;
        int note_tam = (TAM_TEXT + 0x10 * notes[idx].size) - header_sz;
        puts("Enter the new text");
        read_text_input(notes[idx].text + header_sz, note_tam);
    }

    puts("Changes applied!");
}

void
create_note(){
    int idx;
    while (true){
        int available = available_notes_create();
        if(!available){
            puts("There are no pages left to write a new note!\n");
            return;
        }

        puts("Select the note's index");
        print_note_idxs();

        idx = read_int();

        if( (idx < 0 || idx >= MAX_NOTES) || notes[idx].text != NULL || notes[idx].is_written || notes[idx].is_freed ){
            puts("Invalid index!!");
            continue;
        } 
        break;
    }

    int sz;
    while(true){
        puts("Choose the note size [small: 0, med: 1, big: 2]");
        sz = read_int();
        switch (sz){
            case 0:
            case 1:
            case 2:
                break;
            default:
                puts("Invalid note size!!");
                continue;
        }
        break;
    }

    int with_footer;
    while(true){
        puts("Do you want to write a footer to your note? [yes: 1, no: 0]");
        with_footer = read_int();
        switch (with_footer){
            case 0:
            case 1:
                break;

            default:
                puts("Invalid choize!!");
                continue;
        }
        break;
    }

    notes[idx].is_written = true;
    notes[idx].size = (note_sz) sz;

    int total_text_tam = TAM_TEXT + sz * 0x10, text_offset = 0;
    notes[idx].text = (char *) calloc(total_text_tam, 1);

    if(with_footer){
        notes[idx].footer = (char *) calloc(TAM_FOOTER, 1);
    }

    puts("\nFilling the fields...");
    text_offset = fill_fields(idx, with_footer);

    puts("Enter the note's text");
    read_text_input(notes[idx].text + text_offset, total_text_tam - text_offset);

    printf("Note created with index %d\n", idx);
}